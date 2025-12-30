const profaneWords = [
  "fuck", "shit", "bitch", "damn", "crap", "dick", "cock", "pussy", "bastard",
  "whore", "slut", "fag", "nigger", "nigga", "retard", "cunt", "twat", "bollocks",
  "wanker", "prick", "arsehole", "asshole", "motherfucker", "bullshit", "horseshit",
  "dumbass", "jackass", "dipshit", "shithead", "fuckface", "dickhead", "douchebag",
  "scumbag", "piss", "pissed", "goddamn", "bloody", "bugger",
  "tosser", "knob", "bellend", "minger", "slag", "pillock", "plonker",
  "nonce", "chav", "spaz", "spastic", "mongo", "downie",
  "kike", "chink", "gook", "wetback", "beaner", "spic", "cracker", "honky",
  "tranny", "shemale", "dyke", "lesbo", "faggot",
  "kill yourself", "kys", "go die", "neck yourself", "hang yourself"
];

const leetSpeakMap: Record<string, string> = {
  '0': 'o',
  '1': 'i',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '8': 'b',
  '@': 'a',
  '$': 's',
  '!': 'i',
};

function normalizeLeetSpeak(text: string): string {
  let normalized = text.toLowerCase();
  for (const [leet, letter] of Object.entries(leetSpeakMap)) {
    normalized = normalized.replace(new RegExp(leet.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), letter);
  }
  return normalized;
}

function removeRepeatedChars(text: string): string {
  return text.replace(/(.)\1{2,}/g, '$1$1');
}

export type ProfanityCheckResult = {
  isClean: boolean;
  violation: string | null;
  reason: string | null;
};

export function checkProfanity(content: string): ProfanityCheckResult {
  if (!content || content.trim().length === 0) {
    return { isClean: false, violation: "empty", reason: "Message cannot be empty" };
  }

  if (content.length > 2000) {
    return { isClean: false, violation: "length", reason: "Message exceeds 2000 character limit" };
  }

  const normalized = normalizeLeetSpeak(content);
  const withoutRepeats = removeRepeatedChars(normalized);
  const words = withoutRepeats.split(/[\s\-_.,!?]+/);
  
  for (const word of words) {
    for (const profane of profaneWords) {
      if (!profane.includes(' ') && word === profane) {
        return { 
          isClean: false, 
          violation: "profanity", 
          reason: "Message contains inappropriate language that violates our Code of Conduct" 
        };
      }
    }
  }

  for (const phrase of profaneWords.filter(w => w.includes(' '))) {
    if (normalized.includes(phrase)) {
      return { 
        isClean: false, 
        violation: "profanity", 
        reason: "Message contains inappropriate language that violates our Code of Conduct" 
      };
    }
  }

  return { isClean: true, violation: null, reason: null };
}

export const CODE_OF_CONDUCT = `
## CloudShieldLab Community Code of Conduct

### Our Standards

**Be Respectful:** Treat everyone with respect and dignity. No harassment, discrimination, or personal attacks.

**Stay On Topic:** Focus discussions on cloud security, labs, learning, and professional development.

**No Inappropriate Content:** 
- No profanity, slurs, or offensive language
- No hate speech or discriminatory remarks
- No threats or harassment
- No spam or self-promotion

**Help Each Other:** Share knowledge constructively. We're all here to learn and grow as security professionals.

### Consequences

Violations may result in:
1. First offense: Post hidden with warning
2. Repeat offenses: Temporary posting restrictions
3. Severe violations: Permanent ban from community features

### Reporting

If you see content that violates these guidelines, please report it to the community moderators.

*Thank you for helping maintain a positive learning environment!*
`;
