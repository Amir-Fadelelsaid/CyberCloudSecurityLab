import { Link } from "wouter";
import { Terminal, Shield, Lock, ChevronRight } from "lucide-react";
import { motion } from "framer-motion";

export default function Landing() {
  return (
    <div className="min-h-screen bg-background text-foreground overflow-hidden font-sans relative">
      {/* Background Effects */}
      <div className="absolute inset-0 z-0">
        <div className="absolute top-0 left-1/4 w-[500px] h-[500px] bg-primary/10 rounded-full blur-[100px] opacity-30 animate-pulse" />
        <div className="absolute bottom-0 right-1/4 w-[600px] h-[600px] bg-blue-500/10 rounded-full blur-[120px] opacity-20" />
        <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20"></div>
      </div>

      {/* Nav */}
      <nav className="relative z-20 container mx-auto px-6 py-6 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <Terminal className="w-8 h-8 text-primary" />
          <span className="font-display font-bold text-2xl tracking-wider">CYBER<span className="text-primary">LAB</span></span>
        </div>
        <a href="/api/login">
          <button className="px-6 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-sm font-mono transition-all backdrop-blur-sm">
            OPERATOR_LOGIN
          </button>
        </a>
      </nav>

      {/* Hero */}
      <main className="relative z-10 container mx-auto px-6 pt-20 lg:pt-32 pb-20">
        <div className="max-w-4xl mx-auto text-center space-y-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-mono mb-6">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
              </span>
              SYSTEM ONLINE // V1.0.4 ACTIVE
            </div>
            
            <h1 className="text-5xl md:text-7xl font-display font-black leading-tight text-white mb-6">
              MASTER CLOUD <br/>
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary to-emerald-600">SECURITY DEFENSE</span>
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
              <button className="px-8 py-4 rounded-xl bg-primary hover:bg-primary/90 text-background font-bold font-mono flex items-center gap-2 transition-all hover:scale-105 shadow-[0_0_20px_rgba(0,255,128,0.4)]">
                <Terminal className="w-5 h-5" />
                INITIATE_TRAINING
              </button>
            </a>
            <button className="px-8 py-4 rounded-xl bg-card hover:bg-card/80 border border-border text-foreground font-mono font-medium flex items-center gap-2 transition-all">
              VIEW_DOCS <ChevronRight className="w-4 h-4" />
            </button>
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
              color: "from-cyan-500/20 to-blue-500/20",
              borderColor: "border-cyan-500/40",
              shadowColor: "shadow-cyan-500/20"
            },
            { 
              icon: Terminal, 
              title: "CLI-Based Defense", 
              desc: "Use a realistic terminal interface to identify threats and execute remediation scripts.",
              color: "from-primary/20 to-emerald-500/20",
              borderColor: "border-primary/40",
              shadowColor: "shadow-primary/20"
            },
            { 
              icon: Lock, 
              title: "Progress Tracking", 
              desc: "Earn certifications and track your skill growth across IAM, Network, and Storage domains.",
              color: "from-purple-500/20 to-pink-500/20",
              borderColor: "border-purple-500/40",
              shadowColor: "shadow-purple-500/20"
            }
          ].map((feature, i) => (
            <motion.div 
              key={i} 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 + i * 0.1 }}
              whileHover={{ y: -8 }}
              className={`relative overflow-hidden bg-gradient-to-br ${feature.color} backdrop-blur-xl border ${feature.borderColor} p-8 rounded-2xl group cursor-pointer shadow-lg hover:shadow-2xl ${feature.shadowColor} transition-all duration-300`}
            >
              {/* Animated background gradient */}
              <div className="absolute inset-0 bg-gradient-to-tr from-transparent via-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
              
              {/* Glow effect */}
              <div className="absolute -inset-1 bg-gradient-to-br opacity-0 group-hover:opacity-30 blur-xl transition-all duration-300 rounded-2xl" style={{ background: `linear-gradient(to right, ${i === 0 ? '#00d9ff' : i === 1 ? '#00ff80' : '#ff00ff'}, transparent)` }} />
              
              <div className="relative z-10">
                <motion.div 
                  className={`w-14 h-14 rounded-xl bg-gradient-to-br ${feature.color} border ${feature.borderColor} flex items-center justify-center mb-6 group-hover:scale-125 transition-transform duration-300 shadow-lg`}
                  animate={{ 
                    boxShadow: i === 0 ? ["0 0 20px rgba(0, 217, 255, 0.3)", "0 0 40px rgba(0, 217, 255, 0.6)"] :
                               i === 1 ? ["0 0 20px rgba(0, 255, 128, 0.3)", "0 0 40px rgba(0, 255, 128, 0.6)"] :
                               ["0 0 20px rgba(255, 0, 255, 0.3)", "0 0 40px rgba(255, 0, 255, 0.6)"]
                  }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  <feature.icon className="w-7 h-7 text-white" />
                </motion.div>
                <h3 className="text-xl font-bold font-display mb-3 text-white group-hover:text-transparent group-hover:bg-clip-text group-hover:bg-gradient-to-r group-hover:from-primary group-hover:to-accent transition-all duration-300">{feature.title}</h3>
                <p className="text-muted-foreground leading-relaxed group-hover:text-muted-foreground/90 transition-colors">{feature.desc}</p>
              </div>
            </motion.div>
          ))}
        </motion.div>
      </main>
    </div>
  );
}
