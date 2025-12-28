import { useLabs } from "@/hooks/use-labs";
import { Link } from "wouter";
import { motion } from "framer-motion";
import { Loader2, Search, Filter } from "lucide-react";
import { useState } from "react";
import { clsx } from "clsx";

export default function LabsList() {
  const { data: labs, isLoading } = useLabs();
  const [filter, setFilter] = useState('All');
  const [search, setSearch] = useState('');

  const filteredLabs = labs?.filter(lab => {
    const matchesFilter = filter === 'All' || lab.difficulty === filter;
    const matchesSearch = lab.title.toLowerCase().includes(search.toLowerCase()) || 
                          lab.description.toLowerCase().includes(search.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-3xl font-display font-bold text-white mb-2">TRAINING SIMULATIONS</h1>
          <p className="text-muted-foreground">Select a scenario to begin your security assessment.</p>
        </div>
      </div>

      {/* Filters & Search */}
      <div className="flex flex-col md:flex-row gap-4 bg-card p-4 rounded-xl border border-border/50">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input 
            type="text" 
            placeholder="Search missions..." 
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-background/50 border border-border rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50 transition-all"
          />
        </div>
        <div className="flex gap-2 overflow-x-auto pb-2 md:pb-0">
          {['All', 'Beginner', 'Intermediate', 'Advanced'].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFilter(lvl)}
              className={clsx(
                "px-4 py-2 rounded-lg text-sm font-mono whitespace-nowrap transition-all border",
                filter === lvl 
                  ? "bg-primary/10 text-primary border-primary/30" 
                  : "bg-transparent text-muted-foreground border-transparent hover:bg-white/5 hover:text-white"
              )}
            >
              {lvl.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Grid */}
      {isLoading ? (
        <div className="flex justify-center py-20">
          <Loader2 className="w-8 h-8 text-primary animate-spin" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredLabs?.map((lab, index) => (
            <motion.div
              key={lab.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
            >
              <Link href={`/labs/${lab.id}`} className="block h-full">
                <div className="h-full bg-card hover:bg-card/80 border border-border/50 hover:border-primary/50 rounded-xl p-6 flex flex-col transition-all duration-300 group shadow-lg hover:shadow-primary/5 relative overflow-hidden">
                  
                  {/* Category Stripe */}
                  <div className={clsx(
                    "absolute top-0 left-0 w-1 h-full",
                    lab.category === 'IAM' ? "bg-blue-500" :
                    lab.category === 'Network' ? "bg-purple-500" : "bg-orange-500"
                  )} />

                  <div className="flex justify-between items-start mb-4 pl-2">
                     <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest bg-white/5 px-2 py-1 rounded border border-white/5">
                        {lab.category}
                     </span>
                     <span className={clsx(
                        "text-[10px] font-bold px-2 py-0.5 rounded border uppercase",
                        lab.difficulty === 'Beginner' ? "text-green-400 border-green-500/30 bg-green-500/10" :
                        lab.difficulty === 'Intermediate' ? "text-yellow-400 border-yellow-500/30 bg-yellow-500/10" :
                        "text-red-400 border-red-500/30 bg-red-500/10"
                     )}>
                        {lab.difficulty}
                     </span>
                  </div>

                  <h3 className="text-xl font-bold font-display mb-2 group-hover:text-primary transition-colors pl-2">
                    {lab.title}
                  </h3>
                  
                  <p className="text-sm text-muted-foreground flex-1 pl-2 mb-6">
                    {lab.description}
                  </p>

                  <div className="mt-auto pl-2">
                    <div className="w-full py-2.5 rounded-lg bg-primary/10 border border-primary/20 text-primary text-center text-xs font-mono font-bold group-hover:bg-primary group-hover:text-background transition-all uppercase tracking-wider">
                      Initialize Simulation
                    </div>
                  </div>
                </div>
              </Link>
            </motion.div>
          ))}
          
          {filteredLabs?.length === 0 && (
             <div className="col-span-full text-center py-20 text-muted-foreground">
               No missions found matching your criteria.
             </div>
          )}
        </div>
      )}
    </div>
  );
}
