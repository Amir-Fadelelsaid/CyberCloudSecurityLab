import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, buildUrl } from "@shared/routes";
import { type Lab, type Resource } from "@shared/schema";

export function useLabs() {
  return useQuery({
    queryKey: [api.labs.list.path],
    queryFn: async () => {
      const res = await fetch(api.labs.list.path, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch labs");
      return api.labs.list.responses[200].parse(await res.json());
    },
  });
}

export function useLab(id: number) {
  return useQuery({
    queryKey: [api.labs.get.path, id],
    queryFn: async () => {
      const url = buildUrl(api.labs.get.path, { id });
      const res = await fetch(url, { credentials: "include" });
      if (res.status === 404) throw new Error("Lab not found");
      if (!res.ok) throw new Error("Failed to fetch lab");
      return api.labs.get.responses[200].parse(await res.json());
    },
  });
}

export function useLabResources(labId: number) {
  return useQuery({
    queryKey: [api.resources.list.path, labId],
    queryFn: async () => {
      const url = buildUrl(api.resources.list.path, { labId });
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch resources");
      return api.resources.list.responses[200].parse(await res.json());
    },
    // Poll for updates if terminal commands are changing state
    refetchInterval: 2000, 
  });
}

export function useResetLab() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const url = buildUrl(api.labs.reset.path, { id });
      const res = await fetch(url, { 
        method: api.labs.reset.method,
        credentials: "include" 
      });
      if (!res.ok) throw new Error("Failed to reset lab");
      return api.labs.reset.responses[200].parse(await res.json());
    },
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: [api.labs.get.path, id] });
      queryClient.invalidateQueries({ queryKey: [api.resources.list.path, id] });
    },
  });
}
