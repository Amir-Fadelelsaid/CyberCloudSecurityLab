import { Switch, Route, useLocation } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { Layout } from "@/components/layout";
import { useAuth } from "@/hooks/use-auth";
import { Loader2 } from "lucide-react";
import { useEffect } from "react";

// Pages
import Dashboard from "@/pages/dashboard";
import LabsList from "@/pages/labs-list";
import LabWorkspace from "@/pages/lab-workspace";
import Landing from "@/pages/landing";
import HiringManager from "@/pages/hiring-manager";
import Badges from "@/pages/badges";
import Leaderboard from "@/pages/leaderboard";
import MyProgress from "@/pages/progress";
import NotFound from "@/pages/not-found";

function PrivateRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="h-screen w-full flex items-center justify-center bg-background">
        <Loader2 className="w-10 h-10 text-primary animate-spin" />
      </div>
    );
  }

  if (!isAuthenticated) {
    // Redirect to landing if not logged in
    return <Landing />;
  }

  return (
    <Layout>
      <Component />
    </Layout>
  );
}

function Router() {
  const { isAuthenticated, isLoading } = useAuth();
  const [location, setLocation] = useLocation();

  // Handle root route logic
  useEffect(() => {
    if (!isLoading && !isAuthenticated && location !== "/" && !location.startsWith('/api')) {
      // Allow specific routes or redirect to landing logic handled inside components or here
    }
  }, [isAuthenticated, isLoading, location]);

  return (
    <Switch>
      <Route path="/">
        {isLoading ? (
          <div className="h-screen flex items-center justify-center bg-background">
            <Loader2 className="w-8 h-8 text-primary animate-spin" />
          </div>
        ) : isAuthenticated ? (
          <Layout><Dashboard /></Layout>
        ) : (
          <Landing />
        )}
      </Route>
      
      <Route path="/labs" component={() => <PrivateRoute component={LabsList} />} />
      <Route path="/labs/:id" component={() => <PrivateRoute component={LabWorkspace} />} />
      
      {/* My Progress page - personal analytics and stats */}
      <Route path="/progress" component={() => <PrivateRoute component={MyProgress} />} />
      
      {/* Badges page */}
      <Route path="/badges" component={() => <PrivateRoute component={Badges} />} />
      
      {/* Leaderboard page */}
      <Route path="/leaderboard" component={() => <PrivateRoute component={Leaderboard} />} />
      
      {/* Public hiring manager page */}
      <Route path="/hiring" component={HiringManager} />
      
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Toaster />
      <Router />
    </QueryClientProvider>
  );
}

export default App;
