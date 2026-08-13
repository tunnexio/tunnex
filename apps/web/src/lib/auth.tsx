import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { api, type AuthUser } from "./api";

type AuthState =
  | { status: "loading" }
  | { status: "authed"; user: AuthUser }
  | { status: "anon" };

type AuthContextValue = {
  state: AuthState;
  // login records an already-authenticated user (the Login page calls the API).
  setUser: (user: AuthUser) => void;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

/**
 * AuthProvider rehydrates auth state on load by calling GET /auth/me (the session
 * cookie is httpOnly, so this is the only way the SPA learns it is logged in after
 * a refresh). While that request is in flight the state is "loading" so gated
 * routes don't flash the login screen for an already-authenticated user.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    api
      .GET("/api/v1/auth/me")
      .then(({ data, error }) => {
        if (cancelled) return;
        setState(
          data && !error
            ? { status: "authed", user: data }
            : { status: "anon" },
        );
      })
      .catch(() => {
        if (!cancelled) setState({ status: "anon" });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const setUser = (user: AuthUser) => setState({ status: "authed", user });

  const logout = async () => {
    await api.POST("/api/v1/auth/logout", {}).catch(() => {});
    setState({ status: "anon" });
  };

  return (
    <AuthContext.Provider value={{ state, setUser, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
