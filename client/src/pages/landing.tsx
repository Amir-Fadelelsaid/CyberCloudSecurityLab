import { Link } from "wouter";
import { Terminal, Shield, Lock, ChevronRight, Briefcase, AlertTriangle, Award, Users } from "lucide-react";
import { motion } from "framer-motion";

export default function Landing() {
  return (
    <div className="min-h-screen bg-background text-foreground overflow-hidden font-sans relative">
      {/* Background Effects - Subtle and professional */}
      <div className="absolute inset-0 z-0">
        <div className="absolute top-0 left-1/4 w-[600px] h-[600px] bg-primary/15 rounded-full blur-[150px] opacity-40" />
        <div className="absolute bottom-0 right-1/4 w-[700px] h-[700px] bg-blue-600/10 rounded-full blur-[200px] opacity-30" />
        <div className="absolute top-1/2 right-0 w-[500px] h-[500px] bg-accent/10 rounded-full blur-[180px] opacity-25" />
      </div>

      {/* Nav */}
      <nav className="relative z-20 container mx-auto px-6 py-6 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <Terminal className="w-8 h-8 text-primary" />
          <span className="font-display font-bold text-xl tracking-wider">CLOUDSHIELD<span className="text-primary">LAB</span></span>
        </div>
        <div className="flex items-center gap-3">
          <Link href="/hiring">
            <button className="px-4 py-2 rounded-lg text-sm font-medium transition-all text-muted-foreground hover:text-white flex items-center gap-1" data-testid="link-hiring-manager">
              <Briefcase className="w-4 h-4" />
              For Recruiters
            </button>
          </Link>
          <a href="/api/login">
            <button className="px-6 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-sm font-medium transition-all backdrop-blur-sm text-white" data-testid="button-sign-in">
              Sign In
            </button>
          </a>
        </div>
      </nav>

      {/* Hero */}
      <main className="relative z-10 container mx-auto px-6 pt-16 lg:pt-24 pb-16">
        <div className="max-w-4xl mx-auto text-center space-y-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-primary/10 border border-primary/30 text-primary text-xs font-mono mb-6">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-50"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
              </span>
              SYSTEM ONLINE // V2.0 ACTIVE
            </div>
            
            <h1 className="text-5xl md:text-7xl font-display font-black leading-tight text-white mb-6">
              MASTER CLOUD <br/>
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-teal-400 to-cyan-500">SECURITY DEFENSE</span>
            </h1>
            
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto leading-relaxed">
              97 hands-on labs across 7 security domains. Enterprise SOC simulation with SIEM alerts, 
              detection rules, and case management. Earn certificates and level up from Recruit to Elite Defender.
            </p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.6 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4"
          >
            <a href="/api/login">
              <motion.button 
                className="px-8 py-4 rounded-xl bg-gradient-to-r from-teal-600 to-cyan-600 hover:from-teal-500 hover:to-cyan-500 text-white font-bold font-mono flex items-center gap-2 transition-all shadow-lg"
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.98 }}
                data-testid="button-start-training"
              >
                <Terminal className="w-5 h-5" />
                START TRAINING
              </motion.button>
            </a>
            <a href="https://github.com/Amir-Fadelelsaid/CyberSecurityLab" target="_blank" rel="noopener noreferrer">
              <motion.button 
                className="px-8 py-4 rounded-xl bg-white/10 border border-white/20 text-white font-mono font-medium flex items-center gap-2 transition-all hover:bg-white/15"
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.98 }}
                data-testid="button-view-docs"
              >
                VIEW DOCS <ChevronRight className="w-4 h-4" />
              </motion.button>
            </a>
          </motion.div>

          {/* Stats Bar */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3, duration: 0.6 }}
            className="flex justify-center gap-8 pt-8 flex-wrap"
          >
            {[
              { value: "97", label: "Labs" },
              { value: "7", label: "Categories" },
              { value: "23", label: "Badges" },
              { value: "7", label: "Certificates" },
            ].map((stat, i) => (
              <div key={i} className="text-center">
                <p className="text-2xl font-bold text-primary">{stat.value}</p>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">{stat.label}</p>
              </div>
            ))}
          </motion.div>
        </div>

        {/* Feature Grid */}
        <motion.div 
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 0.8 }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mt-20"
        >
          {[
            { 
              icon: Shield, 
              title: "Real-time Simulation", 
              desc: "Interact with mock S3 buckets, EC2 instances, and IAM roles that react to your commands.",
              iconColor: "text-cyan-400"
            },
            { 
              icon: AlertTriangle, 
              title: "SOC Dashboard", 
              desc: "Enterprise SIEM simulation with alerts, logs, detection rules, and case management.",
              iconColor: "text-violet-400"
            },
            { 
              icon: Award, 
              title: "Certificates", 
              desc: "Earn certificates upon completing all labs in a category to prove your skills.",
              iconColor: "text-teal-400"
            },
            { 
              icon: Users, 
              title: "Leaderboard", 
              desc: "Compete with others and track your progress on the live leaderboard.",
              iconColor: "text-orange-400"
            }
          ].map((feature, i) => (
            <motion.div 
              key={i} 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 + i * 0.1, duration: 0.5 }}
              whileHover={{ y: -5 }}
              className="relative rounded-2xl bg-white/5 border border-white/10 p-6 hover:bg-white/8 transition-all group"
            >
              <div className={`w-12 h-12 rounded-xl mb-4 flex items-center justify-center bg-white/5 border border-white/10 ${feature.iconColor}`}>
                <feature.icon className="w-6 h-6" />
              </div>
              <h3 className="text-lg font-bold font-display mb-3 text-white">{feature.title}</h3>
              <p className="text-muted-foreground leading-relaxed text-sm">{feature.desc}</p>
            </motion.div>
          ))}
        </motion.div>

        {/* Categories Preview */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6, duration: 0.8 }}
          className="mt-20"
        >
          <h2 className="text-2xl font-display font-bold text-center text-white mb-8">7 Security Domains</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            {[
              { name: "Storage", count: 12, color: "from-teal-500/20 to-teal-600/10" },
              { name: "Network", count: 17, color: "from-blue-500/20 to-blue-600/10" },
              { name: "SOC Ops", count: 12, color: "from-violet-500/20 to-violet-600/10" },
              { name: "SOC Eng", count: 13, color: "from-orange-500/20 to-orange-600/10" },
              { name: "Cloud Analyst", count: 14, color: "from-cyan-500/20 to-cyan-600/10" },
              { name: "IAM", count: 16, color: "from-yellow-500/20 to-yellow-600/10" },
              { name: "Cloud SecEng", count: 13, color: "from-rose-500/20 to-rose-600/10" },
            ].map((cat, i) => (
              <div key={i} className={`rounded-xl bg-gradient-to-br ${cat.color} border border-white/10 p-4 text-center`}>
                <p className="text-2xl font-bold text-white">{cat.count}</p>
                <p className="text-xs text-muted-foreground">{cat.name}</p>
              </div>
            ))}
          </div>
        </motion.div>
      </main>

      {/* Footer with Credit */}
      <footer className="relative z-10 container mx-auto px-6 py-8 text-center border-t border-white/10">
        <p className="text-sm text-muted-foreground font-mono">
          Created by <span className="text-primary font-medium">Amir Fadelelsaid</span> - SOC Professional & Cloud Security Enthusiast
        </p>
      </footer>
    </div>
  );
}
