import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@shared/routes";

export function useTerminal() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ command, labId }: { command: string; labId: number }) => {
      const res = await fetch(api.terminal.execute.path, {
        method: api.terminal.execute.method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command, labId }),
        credentials: "include",
      });

      if (!res.ok) throw new Error("Command execution failed");
      return api.terminal.execute.responses[200].parse(await res.json());
    },
    onSuccess: (data, variables) => {
      // If the command modified resources, refresh the resource view
      if (data.newState || data.success) {
        // We invalidate the resources list for this lab to show real-time changes (e.g., turning green)
        // We assume the resource list query key pattern from use-labs.ts
        // api.resources.list.path is '/api/labs/:labId/resources'
        // The query key is likely [path, labId]
        queryClient.invalidateQueries({ 
          queryKey: ['/api/labs/:labId/resources', variables.labId] 
        });
        
        // Also refresh progress if lab completed
        if (data.labCompleted) {
           queryClient.invalidateQueries({ queryKey: [api.progress.get.path] });
        }
      }
    },
  });
}
