/** Return an emoji icon for the given instance/job status. */
export function getStatusIcon(status: string): string {
  switch (status) {
    case "provisioning":
    case "pending":
      return "\u{1F7E1}";
    case "running":
      return "\u{1F535}";
    case "active":
    case "completed":
      return "\u{1F7E2}";
    case "stopped":
      return "\u26AB";
    case "failed":
      return "\u{1F534}";
    default:
      return "\u26AA";
  }
}

/** Return a CSS class name for the given instance status. */
export function getStatusClass(status: string): string {
  switch (status) {
    case "provisioning":
      return "status-provisioning";
    case "active":
      return "status-active";
    case "stopped":
      return "status-stopped";
    case "failed":
      return "status-failed";
    default:
      return "";
  }
}
