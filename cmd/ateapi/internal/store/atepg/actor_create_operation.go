// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package atepg

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

var _ store.ActorCreateOperations = (*Persistence)(nil)

// CreateActorOperation commits original response and Actor in ONE transaction.
// Unique operation insertion serializes overlapping retries across processes.
// The immutable original response is intentionally not a current-state lookup.
func (p *Persistence) CreateActorOperation(ctx context.Context, actor *ateapipb.Actor, operationID string, requestHash []byte) (*ateapipb.Actor, error) {
	id, err := uuid.Parse(operationID)
	if err != nil || id.String() != operationID || len(requestHash) != 32 || actor.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		return nil, store.ErrFailedPrecondition
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	// Protect namespace generation during this transaction, without retaining a
	// live FK that could cascade away the operation after target deletion.
	space, name := actor.GetMetadata().GetAtespace(), actor.GetMetadata().GetName()
	var spaceUID string
	err = tx.QueryRow(ctx, "SELECT uid FROM atespaces WHERE name=$1 FOR KEY SHARE", space).Scan(&spaceUID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrFailedPrecondition
	}
	if err != nil {
		return nil, err
	}
	original := proto.CloneOf(actor)
	setCreateMetadata(original.Metadata)
	raw, err := proto.Marshal(original)
	if err != nil {
		return nil, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO actor_create_operations (atespace_uid,operation_id,atespace,actor_name,request_hash,original_actor) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, spaceUID, operationID, space, name, requestHash, raw)
	if err != nil {
		return nil, fmt.Errorf("recording create operation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		var oldSpace, oldName, oldSpaceUID string
		var oldHash, oldRaw []byte
		var retired bool
		err = tx.QueryRow(ctx, `SELECT atespace,actor_name,atespace_uid,request_hash,original_actor,retired FROM actor_create_operations WHERE atespace=$1 AND operation_id=$2`, space, operationID).Scan(&oldSpace, &oldName, &oldSpaceUID, &oldHash, &oldRaw, &retired)
		if err != nil {
			return nil, err
		}
		if oldSpace != space || oldName != name || oldSpaceUID != spaceUID || !bytes.Equal(oldHash, requestHash) {
			return nil, store.ErrFailedPrecondition
		}
		if retired || len(oldRaw) == 0 {
			return nil, store.ErrFailedPrecondition
		} // irrevocably cancelled operation
		result := new(ateapipb.Actor)
		if err = proto.Unmarshal(oldRaw, result); err != nil {
			return nil, fmt.Errorf("decoding original create authority: %w", err)
		}
		if err = tx.Commit(ctx); err != nil {
			return nil, err
		}
		return result, nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO actors (atespace,name,uid,version,proto) VALUES ($1,$2,$3,$4,$5)`, space, name, original.GetMetadata().GetUid(), original.GetMetadata().GetVersion(), raw)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, store.ErrAlreadyExists
		}
		if isForeignKeyViolation(err) {
			return nil, store.ErrFailedPrecondition
		}
		return nil, fmt.Errorf("creating original Actor: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return original, nil
}

// LookupActorCreateOperation does not require the original template or target
// to remain present: both can disappear after a committed Create reply is lost.
func (p *Persistence) LookupActorCreateOperation(ctx context.Context, space, name, operationID string, requestHash []byte) (*ateapipb.Actor, error) {
	id, err := uuid.Parse(operationID)
	if err != nil || id.String() != operationID || len(requestHash) != 32 {
		return nil, store.ErrFailedPrecondition
	}
	var oldUID, currentUID, oldName string
	var oldHash, raw []byte
	var retired bool
	err = p.pool.QueryRow(ctx, `SELECT o.atespace_uid, COALESCE(a.uid,''), o.actor_name, o.request_hash, o.original_actor,o.retired FROM actor_create_operations o LEFT JOIN atespaces a ON a.name=o.atespace WHERE o.atespace=$1 AND o.operation_id=$2`, space, operationID).Scan(&oldUID, &currentUID, &oldName, &oldHash, &raw, &retired)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if oldUID != currentUID || oldName != name || !bytes.Equal(oldHash, requestHash) {
		return nil, store.ErrFailedPrecondition
	}
	if retired || len(raw) == 0 {
		return nil, store.ErrFailedPrecondition
	} // cleanup tombstone, no activation identity
	actor := new(ateapipb.Actor)
	if err = proto.Unmarshal(raw, actor); err != nil {
		return nil, fmt.Errorf("decoding original operation: %w", err)
	}
	return actor, nil
}

// RetireActorCreateOperation races safely with first Create using the SAME
// unique operation key and transaction serialization. Empty original_actor is
// an irreversible cancellation tombstone, never an Actor or a release receipt.
func (p *Persistence) RetireActorCreateOperation(ctx context.Context, space, name, operationID string, requestHash []byte) (*ateapipb.Actor, error) {
	id, err := uuid.Parse(operationID)
	if err != nil || id.String() != operationID || len(requestHash) != 32 {
		return nil, store.ErrFailedPrecondition
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var spaceUID string
	err = tx.QueryRow(ctx, "SELECT uid FROM atespaces WHERE name=$1 FOR KEY SHARE", space).Scan(&spaceUID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrFailedPrecondition
	}
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO actor_create_operations (atespace_uid,operation_id,atespace,actor_name,request_hash,original_actor) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, spaceUID, operationID, space, name, requestHash, []byte{})
	if err != nil {
		return nil, err
	}
	var oldUID, oldName string
	var oldHash, raw []byte
	err = tx.QueryRow(ctx, `SELECT atespace_uid,actor_name,request_hash,original_actor FROM actor_create_operations WHERE atespace=$1 AND operation_id=$2`, space, operationID).Scan(&oldUID, &oldName, &oldHash, &raw)
	if err != nil {
		return nil, err
	}
	if oldUID != spaceUID || oldName != name || !bytes.Equal(oldHash, requestHash) {
		return nil, store.ErrFailedPrecondition
	}
	if _, err = tx.Exec(ctx, `UPDATE actor_create_operations SET retired=true WHERE atespace=$1 AND operation_id=$2`, space, operationID); err != nil {
		return nil, err
	}
	var original *ateapipb.Actor
	if len(raw) > 0 {
		original = new(ateapipb.Actor)
		if err = proto.Unmarshal(raw, original); err != nil {
			return nil, err
		}
	}
	if original != nil {
		// Do not touch a replacement. A missing original target is already gone;
		// retain its cleanup authority without inventing new compute.
		var currentRaw []byte
		e := tx.QueryRow(ctx, `SELECT proto FROM actors WHERE atespace=$1 AND name=$2 AND uid=$3 FOR UPDATE`, space, name, original.GetMetadata().GetUid()).Scan(&currentRaw)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return nil, e
		}
		if e == nil {
			current := new(ateapipb.Actor)
			if e = proto.Unmarshal(currentRaw, current); e != nil {
				return nil, e
			}
			if current.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_DELETING {
				oldMeta := proto.CloneOf(current.Metadata)
				current.Status.State = ateapipb.ActorState_ACTOR_STATE_DELETING
				setUpdateMetadata(current.Metadata, oldMeta)
				currentRaw, e = proto.Marshal(current)
				if e != nil {
					return nil, e
				}
				if _, e = tx.Exec(ctx, `UPDATE actors SET version=$1,proto=$2 WHERE atespace=$3 AND name=$4 AND uid=$5`, current.GetMetadata().GetVersion(), currentRaw, space, name, original.GetMetadata().GetUid()); e != nil {
					return nil, e
				}
			}
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return original, nil
}
