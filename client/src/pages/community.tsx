import { motion } from "framer-motion";
import { Users } from "lucide-react";
import { CommunityDiscussion } from "@/components/community-discussion";

export default function Community() {
  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center gap-4"
      >
        <div className="p-3 rounded-xl bg-primary/10 border border-primary/20">
          <Users className="w-8 h-8 text-primary" />
        </div>
        <div>
          <h1 className="text-2xl font-display font-bold text-white">Community</h1>
          <p className="text-muted-foreground text-sm">Connect with fellow security professionals</p>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <CommunityDiscussion />
      </motion.div>
    </div>
  );
}
