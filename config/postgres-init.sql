-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Shauth and Ory Hydra share one PostgreSQL instance but need isolated
-- databases because they own independent migration histories.
CREATE DATABASE hydra;
