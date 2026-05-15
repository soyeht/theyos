import { useEffect, useRef } from "react";

/**
 * Poll a callback at a fixed interval.
 * Runs immediately on mount, then every `intervalMs`.
 * Cleans up on unmount.
 */
export function usePolling(callback: () => void, intervalMs: number): void {
  const savedCallback = useRef(callback);

  // Update ref on each render so we always call the latest callback
  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);

  useEffect(() => {
    savedCallback.current();
    const id = setInterval(() => savedCallback.current(), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
}
