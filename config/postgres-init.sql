-- SPDX-License-Identifier: AGPL-3.0-or-later
-- The three services share one PostgreSQL instance but require isolated
-- databases because Shauth and Hydra own independent migration histories.
CREATE DATABASE hydra;
