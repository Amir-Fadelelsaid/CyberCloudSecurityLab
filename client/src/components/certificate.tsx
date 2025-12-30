import { forwardRef } from "react";
import { Shield, Award, CheckCircle2 } from "lucide-react";

interface CertificateProps {
  userName: string;
  category: string;
  displayName: string;
  completedAt: string;
  labsCompleted: number;
  skills: string[];
  experience: string;
  className?: string;
}

export const Certificate = forwardRef<HTMLDivElement, CertificateProps>(
  ({ userName, category, displayName, completedAt, labsCompleted, skills, experience, className = "" }, ref) => {
    const formattedDate = new Date(completedAt).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });

    return (
      <div 
        ref={ref}
        className={`relative bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 p-8 rounded-lg border-4 border-primary/60 shadow-2xl ${className}`}
        style={{ width: '800px', minHeight: '600px' }}
        data-testid="certificate-container"
      >
        <div className="absolute inset-0 opacity-5 pointer-events-none" 
          style={{ 
            backgroundImage: 'radial-gradient(circle at 2px 2px, #00ff80 1px, transparent 0)',
            backgroundSize: '40px 40px'
          }} 
        />

        <div className="absolute top-0 left-0 w-full h-2 bg-gradient-to-r from-transparent via-primary to-transparent" />
        <div className="absolute bottom-0 left-0 w-full h-2 bg-gradient-to-r from-transparent via-primary to-transparent" />
        <div className="absolute top-0 left-0 w-2 h-full bg-gradient-to-b from-transparent via-primary to-transparent" />
        <div className="absolute top-0 right-0 w-2 h-full bg-gradient-to-b from-transparent via-primary to-transparent" />

        <div className="relative z-10 flex flex-col items-center text-center h-full">
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-10 h-10 text-primary" />
            <h1 className="text-3xl font-display font-bold text-primary tracking-wider">
              CLOUDSHIELDLAB
            </h1>
            <Shield className="w-10 h-10 text-primary" />
          </div>
          <p className="text-xs font-mono text-muted-foreground tracking-widest mb-6">
            SECURITY TRAINING PLATFORM
          </p>

          <div className="w-24 h-0.5 bg-gradient-to-r from-transparent via-primary to-transparent mb-6" />

          <h2 className="text-2xl font-display text-white mb-2">
            CERTIFICATE OF COMPLETION
          </h2>
          <p className="text-sm text-muted-foreground mb-6">This is to certify that</p>

          <div className="relative mb-6">
            <h3 className="text-4xl font-display font-bold text-white" data-testid="text-certificate-name">
              {userName}
            </h3>
            <div className="absolute -bottom-2 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-primary/50 to-transparent" />
          </div>

          <p className="text-sm text-muted-foreground mb-2">has successfully completed all training modules in</p>

          <div className="bg-primary/10 border border-primary/30 rounded-lg px-6 py-3 mb-6">
            <h4 className="text-2xl font-display font-bold text-primary" data-testid="text-certificate-category">
              {category}
            </h4>
            <p className="text-xs text-muted-foreground mt-1">{labsCompleted} Training Scenarios Completed</p>
          </div>

          <div className="flex items-center gap-2 mb-4">
            <Award className="w-5 h-5 text-yellow-400" />
            <p className="text-sm font-bold text-yellow-400">
              Certified {displayName}
            </p>
            <Award className="w-5 h-5 text-yellow-400" />
          </div>

          <div className="bg-black/30 rounded-lg p-4 mb-6 max-w-lg">
            <p className="text-xs text-muted-foreground mb-2 font-bold uppercase tracking-wider">Skills Acquired</p>
            <div className="flex flex-wrap justify-center gap-2">
              {skills.map((skill, index) => (
                <span key={index} className="flex items-center gap-1 text-xs text-primary/90 bg-primary/10 px-2 py-1 rounded">
                  <CheckCircle2 className="w-3 h-3" />
                  {skill}
                </span>
              ))}
            </div>
          </div>

          <p className="text-xs text-muted-foreground max-w-md mb-6 italic">
            "{experience}"
          </p>

          <div className="mt-auto flex justify-between items-end w-full pt-4">
            <div className="text-left">
              <p className="text-xs text-muted-foreground">Date of Completion</p>
              <p className="text-sm font-mono text-white" data-testid="text-certificate-date">{formattedDate}</p>
            </div>

            <div className="text-center">
              <div className="w-32 h-0.5 bg-white/50 mb-1" />
              <p className="text-sm font-bold text-white">Amir Fadelsaid</p>
              <p className="text-xs text-muted-foreground">Founder & Developer</p>
              <p className="text-xs text-primary font-mono">CloudShieldLab</p>
            </div>

            <div className="text-right">
              <p className="text-xs text-muted-foreground">Certificate ID</p>
              <p className="text-xs font-mono text-primary/70">
                CSL-{category.substring(0, 3).toUpperCase()}-{new Date(completedAt).getTime().toString(36).toUpperCase()}
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }
);

Certificate.displayName = "Certificate";
