import { Link } from "wouter";
import { Terminal, Shield, Lock, ChevronRight, Briefcase } from "lucide-react";
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
          <span className="font-display font-bold text-2xl tracking-wider">CYBER<span className="text-primary">LAB</span></span>
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
      <main className="relative z-10 container mx-auto px-6 pt-20 lg:pt-32 pb-20">
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
              SYSTEM ONLINE // V1.0.4 ACTIVE
            </div>
            
            <h1 className="text-5xl md:text-7xl font-display font-black leading-tight text-white mb-6">
              MASTER CLOUD <br/>
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-teal-400 to-cyan-500">SECURITY DEFENSE</span>
            </h1>
            
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto leading-relaxed">
              Interactive training simulations for the modern security engineer. 
              Find vulnerabilities, patch resources, and secure the cloud in a realistic virtual environment.
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
              >
                VIEW DOCS <ChevronRight className="w-4 h-4" />
              </motion.button>
            </a>
          </motion.div>
        </div>

        {/* Feature Grid */}
        <motion.div 
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 0.8 }}
          className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-24"
        >
          {[
            { 
              icon: Shield, 
              title: "Real-time Simulation", 
              desc: "Interact with mock S3 buckets, EC2 instances, and IAM roles that react to your commands.",
              iconColor: "text-cyan-400"
            },
            { 
              icon: Terminal, 
              title: "CLI-Based Defense", 
              desc: "Use a realistic terminal interface to identify threats and execute remediation scripts.",
              iconColor: "text-teal-400"
            },
            { 
              icon: Lock, 
              title: "Progress Tracking", 
              desc: "Earn certifications and track your skill growth across IAM, Network, and Storage domains.",
              iconColor: "text-violet-400"
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
      </main>

      {/* Footer with Credit */}
      <footer className="relative z-10 container mx-auto px-6 py-8 text-center border-t border-white/10">
        <p className="text-sm text-muted-foreground font-mono">
          Created by <span className="text-primary font-medium">Amir Fadelelsaid</span>
        </p>
      </footer>
    </div>
  );
}
