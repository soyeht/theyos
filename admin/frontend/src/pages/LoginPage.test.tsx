import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../lib/api";
import { LoginPage } from "./LoginPage";

vi.mock("../lib/api", () => ({
  api: {
    login: vi.fn(),
  },
}));

// react-router-dom navigate mock
const mockNavigate = vi.fn();
vi.mock("react-router-dom", async (importOriginal) => {
  const mod = await importOriginal<typeof import("react-router-dom")>();
  return {
    ...mod,
    useNavigate: () => mockNavigate,
  };
});

const mockedApi = api as unknown as { login: ReturnType<typeof vi.fn> };

function renderLoginPage(onLoginSuccess = vi.fn().mockResolvedValue(undefined)) {
  render(
    <MemoryRouter>
      <LoginPage onLoginSuccess={onLoginSuccess} />
    </MemoryRouter>
  );
  return { onLoginSuccess };
}

describe("LoginPage", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders username and password inputs and a sign in button", () => {
    renderLoginPage();
    expect(screen.getByLabelText("username")).toBeInTheDocument();
    expect(screen.getByLabelText("password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "sign in" })).toBeInTheDocument();
  });

  it("calls api.login with entered credentials on submit", async () => {
    mockedApi.login.mockResolvedValue(undefined);
    renderLoginPage();

    await userEvent.type(screen.getByLabelText("username"), "admin");
    await userEvent.type(screen.getByLabelText("password"), "secret");
    await userEvent.click(screen.getByRole("button", { name: "sign in" }));

    await waitFor(() => {
      expect(mockedApi.login).toHaveBeenCalledWith("admin", "secret");
    });
  });

  it("calls onLoginSuccess and navigates to /instances on successful login", async () => {
    mockedApi.login.mockResolvedValue(undefined);
    const { onLoginSuccess } = renderLoginPage();

    await userEvent.type(screen.getByLabelText("username"), "admin");
    await userEvent.type(screen.getByLabelText("password"), "pass");
    await userEvent.click(screen.getByRole("button", { name: "sign in" }));

    await waitFor(() => {
      expect(onLoginSuccess).toHaveBeenCalledTimes(1);
      expect(mockNavigate).toHaveBeenCalledWith("/instances", { replace: true });
    });
  });

  it("shows error message when login fails", async () => {
    mockedApi.login.mockRejectedValue(new Error("invalid credentials"));
    renderLoginPage();

    await userEvent.type(screen.getByLabelText("username"), "admin");
    await userEvent.type(screen.getByLabelText("password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "sign in" }));

    await waitFor(() => {
      expect(screen.getByText("invalid credentials")).toBeInTheDocument();
    });
  });

  it("disables the button while submission is in progress", async () => {
    let resolveLogin!: () => void;
    mockedApi.login.mockReturnValue(new Promise<void>((res) => { resolveLogin = res; }));
    renderLoginPage();

    await userEvent.type(screen.getByLabelText("username"), "admin");
    await userEvent.type(screen.getByLabelText("password"), "pass");
    await userEvent.click(screen.getByRole("button", { name: "sign in" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "signing in..." })).toBeDisabled();
    });

    resolveLogin();
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "sign in" })).not.toBeDisabled();
    });
  });

  it("clears previous error when a new submission starts", async () => {
    mockedApi.login
      .mockRejectedValueOnce(new Error("bad password"))
      .mockResolvedValue(undefined);

    renderLoginPage();

    await userEvent.type(screen.getByLabelText("username"), "admin");
    await userEvent.type(screen.getByLabelText("password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "sign in" }));
    await waitFor(() => expect(screen.getByText("bad password")).toBeInTheDocument());

    await userEvent.clear(screen.getByLabelText("password"));
    await userEvent.type(screen.getByLabelText("password"), "correct");
    await userEvent.click(screen.getByRole("button", { name: "sign in" }));

    await waitFor(() => {
      expect(screen.queryByText("bad password")).not.toBeInTheDocument();
    });
  });
});
