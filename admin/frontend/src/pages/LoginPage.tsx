import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { extractErrorMessage } from "../lib/errors";

type LoginPageProps = {
  onLoginSuccess: () => Promise<void>;
};

export function LoginPage({ onLoginSuccess }: LoginPageProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError(null);

    try {
      await api.login(username, password);
      await onLoginSuccess();
      navigate("/instances", { replace: true });
    } catch (err) {
      setError(extractErrorMessage(err, "login failed"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-screen">
      <section className="login-card">
        <p className="login-brand">&gt; soyeht</p>
        <h1>access</h1>
        <p className="login-help">// sign in with username and password</p>

        <form onSubmit={handleSubmit} className="login-form">
          <label htmlFor="username">username</label>
          <input
            id="username"
            name="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="enter-your-username"
            autoComplete="username"
            required
          />

          <label htmlFor="password">password</label>
          <input
            id="password"
            name="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="enter-your-password"
            autoComplete="current-password"
            required
          />

          {error && <p className="form-error">{error}</p>}

          <button type="submit" disabled={loading}>
            {loading ? "signing in..." : "sign in"}
          </button>
        </form>

        <p className="login-note">sign in with your admin credentials</p>
      </section>
    </div>
  );
}
