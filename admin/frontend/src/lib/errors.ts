/** Extract a human-readable message from an unknown catch value. */
export function extractErrorMessage(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}
