import { useQuery } from "@tanstack/react-query";
import { Certificate } from "@/components/certificate";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Loader2, Award, Download, CheckCircle2, Lock, Eye } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { useState, useRef } from "react";
import type { Certificate as CertificateType } from "@shared/schema";
import { Badge } from "@/components/ui/badge";

interface CategoryMetadata {
  name: string;
  displayName: string;
  skills: string[];
  experience: string;
  description: string;
  color: string;
}

interface UserProfile {
  id: string;
  firstName: string | null;
  lastName: string | null;
  displayName: string | null;
}

interface PreviewData {
  category: string;
  metadata: CategoryMetadata;
  isPreview: true;
}

export default function CertificatesPage() {
  const [selectedCert, setSelectedCert] = useState<CertificateType | null>(null);
  const [previewData, setPreviewData] = useState<PreviewData | null>(null);
  const certificateRef = useRef<HTMLDivElement>(null);

  const { data: certificates, isLoading: certsLoading } = useQuery<CertificateType[]>({
    queryKey: ["/api/user/certificates"],
  });

  const { data: categories, isLoading: catsLoading } = useQuery<Record<string, CategoryMetadata>>({
    queryKey: ["/api/categories"],
  });

  const { data: userProfile } = useQuery<UserProfile>({
    queryKey: ["/api/user/profile"],
  });

  const userName = userProfile?.displayName || 
    [userProfile?.firstName, userProfile?.lastName].filter(Boolean).join(" ") || 
    "Security Professional";

  const isLoading = certsLoading || catsLoading;

  const earnedCategories = new Set(certificates?.map(c => c.category) || []);
  const allCategories = Object.keys(categories || {});

  const handlePrint = () => {
    if (certificateRef.current) {
      const printWindow = window.open('', '_blank');
      if (printWindow) {
        printWindow.document.write(`
          <html>
            <head>
              <title>CloudShieldLab Certificate</title>
              <style>
                body { margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #0a0a0a; }
                .certificate { transform: scale(0.8); transform-origin: center center; }
              </style>
            </head>
            <body>
              ${certificateRef.current.outerHTML}
              <script>window.print(); window.close();</script>
            </body>
          </html>
        `);
        printWindow.document.close();
      }
    }
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center min-h-[400px]">
        <Loader2 className="w-8 h-8 text-primary animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      <div>
        <h1 className="text-3xl font-display font-bold text-white mb-2">CERTIFICATES</h1>
        <p className="text-muted-foreground mb-4">
          Earn certificates by completing all labs in a category. {earnedCategories.size}/{allCategories.length} earned.
        </p>
        <div className="bg-muted/30 border border-border/50 rounded-md px-4 py-3">
          <p className="text-sm text-muted-foreground">
            <span className="font-medium text-foreground">Disclaimer:</span> These are certificates of completion for finishing CloudShieldLab training labs. They are not industry certifications and do not replace professional credentials.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {allCategories.map((category) => {
          const metadata = categories?.[category];
          const cert = certificates?.find(c => c.category === category);
          const isEarned = !!cert;

          return (
            <motion.div
              key={category}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: allCategories.indexOf(category) * 0.1 }}
            >
              <Card
                className={`p-6 cursor-pointer transition-all ${
                  isEarned 
                    ? "border-primary/50 bg-primary/5 hover:border-primary" 
                    : "border-border/50 opacity-60"
                }`}
                onClick={() => isEarned && cert && setSelectedCert(cert)}
                data-testid={`card-certificate-${category.replace(/\s+/g, '-').toLowerCase()}`}
              >
                <div className="flex items-start justify-between mb-4">
                  <div
                    className="w-12 h-12 rounded-lg flex items-center justify-center"
                    style={{ backgroundColor: isEarned ? `${metadata?.color}20` : '#1a1a1a' }}
                  >
                    {isEarned ? (
                      <Award className="w-6 h-6" style={{ color: metadata?.color }} />
                    ) : (
                      <Lock className="w-6 h-6 text-muted-foreground" />
                    )}
                  </div>
                  {isEarned && (
                    <span className="flex items-center gap-1 text-xs text-primary bg-primary/10 px-2 py-1 rounded">
                      <CheckCircle2 className="w-3 h-3" />
                      Earned
                    </span>
                  )}
                </div>

                <h3 className="text-lg font-bold text-white mb-1">{category}</h3>
                <p className="text-sm text-muted-foreground mb-4">{metadata?.description}</p>

                {isEarned && cert ? (
                  <div className="text-xs text-muted-foreground">
                    Completed {new Date(cert.completedAt!).toLocaleDateString()}
                  </div>
                ) : (
                  <div className="flex items-center justify-between">
                    <div className="text-xs text-muted-foreground">
                      Complete all labs to earn
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-xs gap-1"
                      onClick={(e) => {
                        e.stopPropagation();
                        if (metadata) {
                          setPreviewData({ category, metadata, isPreview: true });
                        }
                      }}
                      data-testid={`button-preview-${category.replace(/\s+/g, '-').toLowerCase()}`}
                    >
                      <Eye className="w-3 h-3" />
                      Preview
                    </Button>
                  </div>
                )}
              </Card>
            </motion.div>
          );
        })}
      </div>

      <AnimatePresence>
        {selectedCert && categories?.[selectedCert.category] && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setSelectedCert(null)}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="relative max-w-[90vw] max-h-[90vh] overflow-auto"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="mb-4 flex justify-end gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handlePrint}
                  data-testid="button-download-certificate"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download / Print
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setSelectedCert(null)}
                >
                  Close
                </Button>
              </div>

              <Certificate
                ref={certificateRef}
                userName={userName}
                category={selectedCert.category}
                displayName={categories[selectedCert.category].displayName}
                completedAt={selectedCert.completedAt?.toString() || new Date().toISOString()}
                labsCompleted={selectedCert.labsCompleted}
                skills={categories[selectedCert.category].skills}
                experience={categories[selectedCert.category].experience}
              />
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Preview Modal for locked certificates */}
      <AnimatePresence>
        {previewData && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setPreviewData(null)}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="relative max-w-[90vw] max-h-[90vh] overflow-auto"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="mb-4 flex items-center justify-between gap-4">
                <Badge variant="outline" className="bg-yellow-500/10 text-yellow-400 border-yellow-500/30">
                  <Eye className="w-3 h-3 mr-1" />
                  PREVIEW - Complete all labs to earn this certificate
                </Badge>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setPreviewData(null)}
                >
                  Close
                </Button>
              </div>

              <div className="relative">
                {/* Preview watermark overlay */}
                <div className="absolute inset-0 pointer-events-none z-10 flex items-center justify-center opacity-20">
                  <div className="text-6xl font-bold text-white transform -rotate-45 select-none">
                    PREVIEW
                  </div>
                </div>
                
                <Certificate
                  userName={userName}
                  category={previewData.category}
                  displayName={previewData.metadata.displayName}
                  completedAt={new Date().toISOString()}
                  labsCompleted={0}
                  skills={previewData.metadata.skills}
                  experience={previewData.metadata.experience}
                />
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
