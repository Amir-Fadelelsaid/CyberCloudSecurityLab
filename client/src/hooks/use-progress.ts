import { useQuery } from "@tanstack/react-query";
import { api } from "@shared/routes";

export function useProgress() {
  return useQuery({
    queryKey: [api.progress.get.path],
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
    staleTime: 0,
    refetchOnMount: true,
    refetchOnWindowFocus: true,
  });
}
