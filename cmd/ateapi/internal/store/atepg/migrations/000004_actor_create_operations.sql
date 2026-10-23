-- Copyright 2026 Google LLC
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- +goose Up
-- Deliberately no target FK: deleting Actor or atespace must not erase original
-- operation authority or permit retry to create replacement compute.
CREATE TABLE actor_create_operations (
 atespace_uid text NOT NULL,
 operation_id text NOT NULL,
 atespace text NOT NULL,
 actor_name text NOT NULL,
 request_hash bytea NOT NULL,
 original_actor bytea NOT NULL,
 PRIMARY KEY (atespace, operation_id)
);
