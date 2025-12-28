import { Link } from "wouter";
import { Terminal, Shield, Lock, ChevronRight } from "lucide-react";
import { motion } from "framer-motion";

export default function Landing() {
  return (
    <div className="min-h-screen bg-background text-foreground overflow-hidden font-sans relative">
      {/* Background Effects - Much more vibrant */}
      <div className="absolute inset-0 z-0">
        <div className="absolute top-0 left-1/4 w-[800px] h-[800px] bg-primary/40 rounded-full blur-[150px] opacity-60 animate-pulse" />
        <div className="absolute bottom-0 right-1/4 w-[900px] h-[900px] bg-blue-500/30 rounded-full blur-[200px] opacity-50 animate-pulse" style={{animationDelay: '1s'}} />
        <div className="absolute top-1/2 right-0 w-[700px] h-[700px] bg-accent/30 rounded-full blur-[180px] opacity-40 animate-pulse" style={{animationDelay: '2s'}} />
        <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-10"></div>
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
              <motion.button 
                className="px-8 py-4 rounded-xl bg-gradient-to-r from-primary to-emerald-500 hover:from-primary hover:to-primary text-background font-bold font-mono flex items-center gap-2 transition-all shadow-[0_0_30px_rgba(0,255,128,0.7)] hover:shadow-[0_0_50px_rgba(0,255,128,1)]"
                whileHover={{ scale: 1.15 }}
                whileTap={{ scale: 0.95 }}
                animate={{ 
                  boxShadow: ["0 0 20px rgba(0,255,128,0.5)", "0 0 40px rgba(0,255,128,0.8)", "0 0 20px rgba(0,255,128,0.5)"]
                }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                <Terminal className="w-5 h-5" />
                INITIATE_TRAINING
              </motion.button>
            </a>
            <motion.button 
              className="px-8 py-4 rounded-xl bg-gradient-to-r from-accent/30 to-purple-600/30 border-2 border-accent text-accent font-mono font-bold flex items-center gap-2 transition-all shadow-[0_0_20px_rgba(160,0,255,0.5)]"
              whileHover={{ scale: 1.1, boxShadow: "0 0 40px rgba(160,0,255,0.8)" }}
              whileTap={{ scale: 0.95 }}
            >
              VIEW_DOCS <ChevronRight className="w-4 h-4" />
            </motion.button>
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
              gradColor: "from-cyan-400 via-blue-500 to-cyan-400",
              glowColor: "rgba(0, 220, 255, 0.8)"
            },
            { 
              icon: Terminal, 
              title: "CLI-Based Defense", 
              desc: "Use a realistic terminal interface to identify threats and execute remediation scripts.",
              gradColor: "from-green-400 via-emerald-500 to-green-400",
              glowColor: "rgba(0, 255, 128, 0.8)"
            },
            { 
              icon: Lock, 
              title: "Progress Tracking", 
              desc: "Earn certifications and track your skill growth across IAM, Network, and Storage domains.",
              gradColor: "from-purple-400 via-pink-500 to-purple-400",
              glowColor: "rgba(255, 0, 255, 0.8)"
            }
          ].map((feature, i) => (
            <motion.div 
              key={i} 
              initial={{ opacity: 0, y: 30, scale: 0.9 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              transition={{ delay: 0.5 + i * 0.15, duration: 0.6 }}
              whileHover={{ y: -15, scale: 1.05 }}
              className="relative overflow-hidden rounded-3xl group cursor-pointer"
            >
              {/* Outer glow container */}
              <motion.div 
                className="absolute -inset-2 rounded-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 blur-2xl"
                style={{ background: `linear-gradient(135deg, ${feature.glowColor}, rgba(0,0,0,0))` }}
                animate={{ 
                  boxShadow: `0 0 40px ${feature.glowColor}, 0 0 80px ${feature.glowColor}`
                }}
                transition={{ duration: 2, repeat: Infinity }}
              />
              
              {/* Main card */}
              <div className={`relative z-10 bg-gradient-to-br ${feature.gradColor} opacity-10 group-hover:opacity-100 transition-opacity duration-300 p-8 rounded-3xl border-2 group-hover:border-4 transition-all`} style={{ borderColor: feature.glowColor }} >
                <div className="absolute inset-0 bg-background/80 rounded-3xl" />
                <div className={`absolute inset-0 bg-gradient-to-br ${feature.gradColor} opacity-0 group-hover:opacity-30 transition-opacity duration-500 rounded-3xl`} />
              </div>
              
              {/* Content */}
              <div className="relative z-20 p-8">
                <motion.div 
                  className="w-16 h-16 rounded-2xl mb-6 flex items-center justify-center border-2 transition-all"
                  style={{ borderColor: feature.glowColor, backgroundColor: `${feature.glowColor}20` }}
                  whileHover={{ scale: 1.3, rotate: 360 }}
                  animate={{ 
                    boxShadow: `0 0 25px ${feature.glowColor}, inset 0 0 15px ${feature.glowColor}40`
                  }}
                  transition={{ duration: 2, repeat: Infinity, rotate: { duration: 0.6 } }}
                >
                  <feature.icon className="w-8 h-8" style={{ color: feature.glowColor }} />
                </motion.div>
                <h3 className="text-2xl font-bold font-display mb-4 text-white group-hover:text-transparent group-hover:bg-clip-text transition-all duration-300" style={{ backgroundImage: `linear-gradient(135deg, ${feature.glowColor}, #ffffff)` }}>{feature.title}</h3>
                <p className="text-muted-foreground/80 leading-relaxed group-hover:text-muted-foreground transition-colors text-base">{feature.desc}</p>
              </div>
              
              {/* Top glow line */}
              <motion.div 
                className="absolute top-0 left-0 right-0 h-[2px] opacity-0 group-hover:opacity-100 transition-opacity"
                style={{ background: `linear-gradient(90deg, transparent, ${feature.glowColor}, transparent)` }}
                animate={{ x: [-100, 300] }}
                transition={{ duration: 2, repeat: Infinity }}
              />
            </motion.div>
          ))}
        </motion.div>
      </main>
    </div>
  );
}
