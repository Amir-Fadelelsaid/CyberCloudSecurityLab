import { useQuery } from "@tanstack/react-query";
import { api } from "@shared/routes";
import { useAuth } from "./use-auth";

export function useProgress() {
  const { user } = useAuth();
  
  return useQuery({
    queryKey: [api.progress.get.path, user?.id],
    queryFn: async () => {
      const res = await fetch(api.progress.get.path, { 
        credentials: "include",
        headers: {
          "Cache-Control": "no-cache"
        }
      });
      if (!res.ok) throw new Error("Failed to fetch progress");
      return api.progress.get.responses[200].parse(await res.json());
    },
    enabled: !!user,
    staleTime: 0,
    refetchOnMount: "always",
    refetchOnWindowFocus: true,
  });
}
