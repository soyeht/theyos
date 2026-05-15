-- Migration 002: add guest_os and aux_storage_path columns to instances table.
--
-- guest_os: 'linux' | 'macos' — VM guest OS type.
--   Default 'linux' preserves compatibility with all existing instances.
-- aux_storage_path: path to VZMacAuxiliaryStorage file (~1 MB .auxstorage).
--   Only populated for macOS guest VMs (NULL for Linux guests).
--
-- Decision 9 from research.md: platform selection at compile time via
-- cfg(target_os = "macos"). The guest_os column is for display and diagnostics.
ALTER TABLE instances ADD COLUMN guest_os TEXT NOT NULL DEFAULT 'linux';
ALTER TABLE instances ADD COLUMN aux_storage_path TEXT;
