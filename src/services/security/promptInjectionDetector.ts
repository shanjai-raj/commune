/**
 * Prompt Injection Detection for AI Agents (v2)
 *
 * Detection-only pipeline:
 *   canonicalize -> heuristic scoring -> structured LLM adjudication -> fusion.
 *
 * Never blocks delivery. Returns metadata for downstream agent decisions.
 */

import logger from '../../utils/logger';
import { canonicalizePromptInputs } from './promptCanonicalizer';
import { PromptSafetyAdjudicatorService } from './promptSafetyAdjudicatorService';
import { fusePromptRisk } from './promptRiskFusion';
import type {
  HeuristicAnalysisResult,
  InjectionAnalysis,
  InjectionSignal,
  PromptInjectionSignals,
} from './promptDetectionTypes';

const DETECTOR_ENABLED = process.env.PROMPT_INJECTION_DETECTOR_ENABLED !== 'false';
const SHADOW_MODE = process.env.PROMPT_INJECTION_SHADOW_MODE === 'true';
const FUSION_VERSION = process.env.PROMPT_INJECTION_FUSION_VERSION || 'v1';
const DETECTION_POLICY_VERSION = process.env.PROMPT_INJECTION_POLICY_VERSION || 'v2';
const MAX_ANALYSIS_LENGTH = 50_000;

const ROLE_OVERRIDE_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts|rules|context)/i,
  /ignore\s+your\s+(instructions|programming|rules|guidelines|system\s+prompt)/i,
  /you\s+are\s+now\s+(a\s+|an\s+)?/i,
  /act\s+as\s+(a\s+|an\s+)?(?!if\b)/i,
  /your\s+new\s+(instructions?|role|purpose|task|objective)\s+(is|are)/i,
  /from\s+now\s+on\s+you\s+(will|should|must|are)/i,
  /forget\s+(everything|all|your\s+(previous|prior|original))/i,
  /disregard\s+(all|your|previous|the\s+above|prior)\s*(instructions|rules|guidelines)?/i,
  /do\s+not\s+follow\s+your\s+(original|previous|initial|system)/i,
  /override\s+(your|the|all)\s+(instructions|rules|guidelines|system\s+prompt)/i,
  /new\s+system\s+prompt\s*:/i,
  /entering\s+(maintenance|debug|developer|admin)\s+mode/i,
  /switch\s+to\s+(unrestricted|unfiltered|jailbreak|developer)\s+mode/i,
  /you\s+have\s+been\s+(reprogrammed|updated|reconfigured)/i,
  /pretend\s+(you\s+are|to\s+be|that\s+you)/i,
  /roleplay\s+as/i,
  /assume\s+the\s+(role|identity|persona)\s+of/i,
  // Conditional AI-targeting injections ("If you are an AI / LLM / assistant...")
  /if\s+you\s+are\s+(a\s+|an\s+)?(ai|llm|language\s+model|assistant|bot|chatbot|gpt)\b/i,
];

const DELIMITER_PATTERNS: RegExp[] = [
  /\[INST\]/i,
  /\[\/INST\]/i,
  /<<SYS>>/i,
  /<<\/SYS>>/i,
  /<\|im_start\|>/i,
  /<\|im_end\|>/i,
  /<\|system\|>/i,
  /<\|user\|>/i,
  /<\|assistant\|>/i,
  /\n\nHuman:/,
  /\n\nAssistant:/,
  /###\s*(System|User|Assistant)\s*:/i,
  /---\s*BEGIN\s+SYSTEM\s+PROMPT\s*---/i,
  /---\s*END\s+SYSTEM\s+PROMPT\s*---/i,
  /SYSTEM\s+OVERRIDE/i,
  /<\|endoftext\|>/i,
  /<\|pad\|>/i,
  /\[SYSTEM\]/i,
  /<system>/i,
  /<\/system>/i,
];

const EXFILTRATION_PATTERNS: RegExp[] = [
  /forward\s+(all|every|each)\s+(email|message|conversation|data)/i,
  /send\s+(all|every|each|the)\s+(data|information|emails|messages|conversations?)\s+to/i,
  /include\s+(the|your|all)\s+(conversation|thread|history|context|system\s+prompt)/i,
  /reply\s+with\s+(your|the)\s+(system\s+prompt|instructions|configuration|rules)/i,
  /what\s+are\s+your\s+(instructions|rules|guidelines|system\s+prompt)/i,
  /output\s+(your|the)\s+(system|initial)\s+(prompt|instructions)/i,
  /repeat\s+(your|the)\s+(system|initial|original)\s+(prompt|instructions)/i,
  /email\s+me\s+(your|the|all)\s+(data|conversations?|context|system)/i,
  /print\s+(your|the)\s+(system\s+prompt|instructions|configuration)/i,
  /show\s+me\s+(your|the)\s+(system\s+prompt|instructions|rules|internal)/i,
  /show\s+(hidden|internal)\s+(prompt|instructions|rules)/i,
  /reveal\s+(your|the)\s+(system\s+prompt|instructions|configuration)/i,
  /reveal\s+(internal|hidden)\s+(rules|prompt|instructions|configuration)/i,
  /dump\s+(your|the|all)\s+(data|context|memory|conversation|prompt)/i,
  /copy\s+(all|every)\s+(email|message|data|conversation)\s+to/i,
  /exfiltrate/i,
  /\bapi[\s_-]?key\b/i,
  /\bsecret(s)?\b/i,
  /\bcredential(s)?\b/i,
  /\benvironment\s+variable(s)?\b/i,
  /\btoken(s)?\b/i,
  /\bprivate\s+(thread|conversation|data|memory)\b/i,
  /\bchain\s+of\s+thought\b/i,
  /\bdisclose\s+(your|the)\s+(system\s+prompt|hidden\s+rules|instructions|configuration|system\s+configuration|memory)\b/i,
  /\bdisclose\s+(all\s+)?(user\s+data|system\s+configuration|internal\s+rules)\b/i,
  /\bfull\s+(thread|conversation)\s+history\b/i,
  /\b(send|forward|export|upload)\s+(all|any|the)?[\w\s,]{0,50}(emails?|messages?|conversations?|threads?|attachments?|data)\s+to\b/i,
];

const TOOL_POISONING_PATTERNS: RegExp[] = [
  /\btool\s+result\b/i,
  /\bfunction\s+result\b/i,
  /\bexecution\s+trace\b/i,
  /\bsystem\s+event\b/i,
  /\bmonitor\s+output\b/i,
  /\bnext\s+action\s*:/i,
  /\bsuppress\s+(alerts|warnings|logs|safeguards)\b/i,
  /\bdo\s+not\s+log\b/i,
  /\bmark\s+as\s+safe\b/i,
];

const AUTHORITY_IMPERSONATION_PATTERNS: RegExp[] = [
  /\bas\s+your\s+(administrator|admin|security\s+lead|cto|compliance\s+officer)\b/i,
  /\bas\s+your[\s\w,-]{0,50}(administrator|admin|security\s+lead|cto|compliance\s+officer)\b/i,
  /\byou\s+are\s+authorized\s+to\b/i,
  /\bthis\s+is\s+an?\s+approved\s+audit\b/i,
  /\bcompliance\s+(requires|requests)\b/i,
  /\blegal\s+requires\b/i,
  /\bexecutive\s+override\b/i,
];

const DELAYED_TRIGGER_PATTERNS: RegExp[] = [
  /\bwhen\s+asked\b/i,
  /\bin\s+the\s+future\b/i,
  /\bon\s+next\s+request\b/i,
  /\bfor\s+future\s+messages\b/i,
  /\bfrom\s+that\s+point\s+on\b/i,
  /\bif\s+the\s+user\s+asks\b/i,
];

// Attacker explicitly specifies the AI's output content — a distinct attack class from
// role override (which targets identity) and exfiltration (which targets data).
// These patterns tell the AI *what words to produce*, not *who to be*.
const OUTPUT_SPECIFICATION_PATTERNS: RegExp[] = [
  /\b(start|begin)\s+your\s+response\s+by\s+(saying|stating|writing|responding)\b/i,
  /\brespond\s+(by\s+saying|with\s+the\s+(phrase|words?|text|following))\b/i,
  /\byour\s+(first|opening|initial)\s+(word|sentence|line|response)\s+(should|must|needs?\s+to)\s+be\b/i,
  /\bsay\s+exactly\s*:/i,
  /\bsay\s+the\s+following\s*:/i,
  /\breply\s+with\s+only\s+the\s+(word|phrase|text|following)\b/i,
  /\bwrite\s+only\s*(:\s*)?(the\s+)?(word|phrase|text|following|this)\b/i,
];

const MANY_SHOT_COERCION_PATTERNS: RegExp[] = [
  /\bexample\s+\d+\b/i,
  /\bassistant\s+reveals\b/i,
  /\bnow\s+do\s+the\s+same\b/i,
  /\bfollow\s+the\s+above\s+examples\b/i,
  /\bpattern\s+to\s+imitate\b/i,
];

const SECURITY_CONTEXT_SUPPRESSORS: RegExp[] = [
  /\bsecurity\s+training\b/i,
  /\btraining\s+only\b/i,
  /\bexample\s+prompt\s+injection\b/i,
  /\bdetect(ing)?\s+prompt\s+injection\b/i,
  /\bjailbreak\s+mitigation\b/i,
  /\bred\s+team(ing)?\b/i,
  /\bthis\s+is\s+an?\s+example\b/i,
  /\bfor\s+educational\s+purposes\b/i,
  /\bknown\s+attack\s+phrase\b/i,
  /\bdo\s+not\s+execute\b/i,
  /```[\s\S]*?(ignore|system prompt|jailbreak)[\s\S]*?```/i,
];

const rot13 = (s: string): string =>
  s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });

const clamp = (value: number, min = 0, max = 1): number => Math.max(min, Math.min(max, value));

class PromptInjectionDetector {
  private static instance: PromptInjectionDetector;
  private readonly adjudicator = PromptSafetyAdjudicatorService.getInstance();

  private constructor() {}

  public static getInstance(): PromptInjectionDetector {
    if (!PromptInjectionDetector.instance) {
      PromptInjectionDetector.instance = new PromptInjectionDetector();
    }
    return PromptInjectionDetector.instance;
  }

  async analyze(
    content: string,
    html?: string,
    subject?: string,
    options?: { enableAdjudicator?: boolean }
  ): Promise<InjectionAnalysis> {
    if (!DETECTOR_ENABLED) {
      return {
        detected: false,
        confidence: 0,
        risk_level: 'none',
        signals: {
          role_override: { score: 0, matches: [] },
          delimiter_injection: { score: 0, matches: [] },
          hidden_text: { score: 0, matches: [] },
          data_exfiltration: { score: 0, matches: [] },
          encoding_obfuscation: { score: 0, matches: [] },
          output_specification: { score: 0, matches: [] },
        },
        summary: 'Prompt injection detector disabled',
        reason_codes: ['detector_disabled'],
        heuristic_score: 0,
        model_checked: false,
        fusion_score: 0,
        fusion_version: FUSION_VERSION,
      };
    }

    const canonical = canonicalizePromptInputs({
      subject: (subject || '').slice(0, MAX_ANALYSIS_LENGTH),
      text: (content || '').slice(0, MAX_ANALYSIS_LENGTH),
      html: (html || '').slice(0, MAX_ANALYSIS_LENGTH),
    });

    const heuristic = this.runHeuristicAnalysis(
      canonical.canonical_text,
      canonical.raw_compact_text,
      canonical.hidden_texts
    );
    const shouldUseAdjudicator = options?.enableAdjudicator !== false;
    const adjudicator = shouldUseAdjudicator
      ? await this.adjudicator.adjudicate(canonical, heuristic)
      : {
        checked: false,
        provider: 'azure-openai-compatible',
        model_version: process.env.PROMPT_INJECTION_ADJUDICATOR_DEPLOYMENT || process.env.AZURE_OPENAI_DEPLOYMENT || 'grok-3-mini',
        score: 0,
        confidence: 0,
        risk_level: 'none' as const,
        is_prompt_injection: false,
        attack_categories: [],
        exfiltration_intent: false,
        obfuscation_detected: false,
        reason_codes: [],
        error_code: 'adjudicator_plan_gated',
      };
    const fusion = fusePromptRisk({
      heuristic,
      adjudicator,
      shadow_mode: SHADOW_MODE,
      fusion_version: FUSION_VERSION,
    });

    if (fusion.detected) {
      logger.warn('Prompt injection detected', {
        risk_level: fusion.risk_level,
        heuristic_score: heuristic.score,
        model_checked: fusion.model_checked,
        model_score: fusion.model_score,
        fusion_score: fusion.score,
        disagreement: fusion.disagreement,
        policy_version: DETECTION_POLICY_VERSION,
      });
    }

    return {
      detected: fusion.detected,
      confidence: fusion.score,
      risk_level: fusion.risk_level,
      signals: heuristic.signals,
      summary: this.buildSummary(fusion.risk_level, heuristic.signals, fusion.reason_codes),
      reason_codes: fusion.reason_codes,
      heuristic_score: heuristic.score,
      model_checked: fusion.model_checked,
      model_provider: fusion.model_provider,
      model_version: fusion.model_version,
      model_score: fusion.model_score,
      model_error: fusion.model_error,
      fusion_score: fusion.score,
      fusion_version: FUSION_VERSION,
      disagreement: fusion.disagreement,
    };
  }

  private runHeuristicAnalysis(
    text: string,
    rawText: string,
    hiddenTexts: string[]
  ): HeuristicAnalysisResult {
    const roleOverride = this.detectPatternList(text, ROLE_OVERRIDE_PATTERNS, 0.3, 80);
    const delimiterInjection = this.detectDelimiterInjection(text);
    const hiddenText = this.detectHiddenText(hiddenTexts);
    const dataExfiltration = this.detectPatternList(text, EXFILTRATION_PATTERNS, 0.4, 80);
    const encodingObfuscation = this.detectEncodingObfuscation(rawText);
    const toolPoisoning = this.detectPatternList(text, TOOL_POISONING_PATTERNS, 0.35, 90);
    const outputSpecification = this.detectPatternList(text, OUTPUT_SPECIFICATION_PATTERNS, 0.35, 90);
    const authorityImpersonation = this.detectPatternList(text, AUTHORITY_IMPERSONATION_PATTERNS, 0.3, 90);
    const delayedTrigger = this.detectPatternList(text, DELAYED_TRIGGER_PATTERNS, 0.2, 90);
    const manyShotCoercion = this.detectPatternList(text, MANY_SHOT_COERCION_PATTERNS, 0.2, 90);
    const suppressor = this.detectSuppressor(text);

    const baseScore = (
      roleOverride.score * 0.24 +
      delimiterInjection.score * 0.12 +
      hiddenText.score * 0.2 +
      dataExfiltration.score * 0.18 +
      encodingObfuscation.score * 0.08 +
      toolPoisoning.score * 0.09 +
      outputSpecification.score * 0.10 +
      authorityImpersonation.score * 0.05 +
      delayedTrigger.score * 0.02 +
      manyShotCoercion.score * 0.02
    );

    const hasSensitiveExfiltration = dataExfiltration.matches.some((match) =>
      /\bsystem\s+prompt\b|\bhidden\s+rules\b|\bconversation\s+history\b|\bapi[\s_-]?key\b|\bsecret\b|\btoken\b/i.test(match)
    );
    const strongRoleHijack = roleOverride.matches.some((match) =>
      /\b(ignore|forget|disregard|override|reprogrammed|unrestricted|developer|admin)\b/i.test(match)
    );
    const delimiterWithCommand =
      delimiterInjection.score >= 0.8 &&
      /\b(ignore|override|reveal|dump|show|disclose|exfiltrate|execute|run)\b/i.test(text);
    const manyShotExfiltrationCombo = manyShotCoercion.score >= 0.2 && dataExfiltration.score >= 0.4;

    let conjunctionBoost = 0;
    if (roleOverride.score >= 0.3 && dataExfiltration.score >= 0.4) {
      conjunctionBoost += 0.28;
    }
    if (toolPoisoning.score >= 0.35 && dataExfiltration.score >= 0.4) {
      conjunctionBoost += 0.24;
    }
    if (authorityImpersonation.score >= 0.3 && dataExfiltration.score >= 0.4) {
      conjunctionBoost += 0.18;
    }
    if (delayedTrigger.score >= 0.2 && roleOverride.score >= 0.3) {
      conjunctionBoost += 0.12;
    }
    if (manyShotExfiltrationCombo) {
      conjunctionBoost += 0.24;
    }
    if (hasSensitiveExfiltration) {
      conjunctionBoost += 0.22;
    }
    if (strongRoleHijack) {
      conjunctionBoost += 0.16;
    }
    if (delimiterWithCommand) {
      conjunctionBoost += 0.22;
    }
    if (roleOverride.score >= 0.3 && encodingObfuscation.score >= 0.25) {
      conjunctionBoost += 0.12;
    }
    // AI-targeting + explicit output command = deliberate behavioral hijack
    if (roleOverride.score >= 0.3 && outputSpecification.score >= 0.35) {
      conjunctionBoost += 0.30;
    }

    const rawScore = clamp(baseScore + conjunctionBoost);

    const hardMaliciousSignals =
      hiddenText.technique === 'hidden_instruction' ||
      (roleOverride.score >= 0.3 && dataExfiltration.score >= 0.4) ||
      (toolPoisoning.score >= 0.35 && dataExfiltration.score >= 0.4);

    const suppressionFactor = hardMaliciousSignals
      ? 1 - (suppressor.score * 0.15)
      : 1 - (suppressor.score * 0.45);

    const score = clamp(rawScore * suppressionFactor);

    const reasonCodes: string[] = [];
    if (roleOverride.score > 0) reasonCodes.push('role_override_detected');
    if (delimiterInjection.score > 0) reasonCodes.push('delimiter_injection_detected');
    if (hiddenText.score > 0) reasonCodes.push(`hidden_text_${hiddenText.technique || 'detected'}`);
    if (dataExfiltration.score > 0) reasonCodes.push('data_exfiltration_detected');
    if (hasSensitiveExfiltration) reasonCodes.push('sensitive_exfiltration_detected');
    if (encodingObfuscation.score > 0) reasonCodes.push('encoding_obfuscation_detected');
    if (toolPoisoning.score > 0) reasonCodes.push('tool_poisoning_detected');
    if (outputSpecification.score > 0) reasonCodes.push('output_specification_detected');
    if (roleOverride.score >= 0.3 && outputSpecification.score >= 0.35) reasonCodes.push('ai_targeting_output_hijack_combo');
    if (authorityImpersonation.score > 0) reasonCodes.push('authority_impersonation_detected');
    if (delayedTrigger.score > 0) reasonCodes.push('delayed_trigger_detected');
    if (manyShotCoercion.score > 0) reasonCodes.push('many_shot_coercion_detected');
    if (manyShotExfiltrationCombo) reasonCodes.push('many_shot_exfiltration_combo');
    if (roleOverride.score >= 0.3 && dataExfiltration.score >= 0.4) {
      reasonCodes.push('direct_hijack_exfiltration_combo');
    }
    if (strongRoleHijack) reasonCodes.push('strong_role_hijack_detected');
    if (delimiterWithCommand) reasonCodes.push('delimiter_command_combo');
    if (toolPoisoning.score >= 0.35 && dataExfiltration.score >= 0.4) {
      reasonCodes.push('tool_poisoning_exfiltration_combo');
    }
    if (authorityImpersonation.score >= 0.3 && dataExfiltration.score >= 0.4) {
      reasonCodes.push('authority_laundering_exfiltration_combo');
    }
    if (suppressor.score > 0) reasonCodes.push('contextual_suppressor_detected');

    const signals: PromptInjectionSignals = {
      role_override: roleOverride,
      delimiter_injection: delimiterInjection,
      hidden_text: hiddenText,
      data_exfiltration: dataExfiltration,
      encoding_obfuscation: encodingObfuscation,
      output_specification: outputSpecification,
    };

    return {
      score: Math.round(score * 1000) / 1000,
      suppressor_score: suppressor.score,
      signals,
      reason_codes: reasonCodes,
      has_high_confidence_hidden_instruction: hiddenText.technique === 'hidden_instruction',
      has_exfiltration_intent: dataExfiltration.score >= 0.4,
      has_obfuscation_intent: encodingObfuscation.score >= 0.25,
    };
  }

  private detectPatternList(
    text: string,
    patterns: RegExp[],
    multiplier: number,
    maxSnippetLength: number
  ): InjectionSignal {
    const matches: string[] = [];
    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match) matches.push(match[0].trim().slice(0, maxSnippetLength));
    }
    return {
      score: clamp(matches.length * multiplier),
      matches,
    };
  }

  private detectDelimiterInjection(text: string): InjectionSignal {
    const matches: string[] = [];
    for (const pattern of DELIMITER_PATTERNS) {
      const match = text.match(pattern);
      if (match) matches.push(match[0].trim().slice(0, 40));
    }
    if (matches.length === 1) return { score: 0.8, matches };
    if (matches.length > 1) return { score: 1.0, matches };
    return { score: 0, matches };
  }

  private detectHiddenText(hiddenTexts: string[]): InjectionSignal {
    if (hiddenTexts.length === 0) return { score: 0, matches: [] };
    const combinedHidden = hiddenTexts.join(' ').toLowerCase();
    const hiddenInstructionMatches: string[] = [];

    for (const pattern of ROLE_OVERRIDE_PATTERNS) {
      const match = combinedHidden.match(pattern);
      if (match) hiddenInstructionMatches.push(match[0].trim().slice(0, 80));
    }
    for (const pattern of EXFILTRATION_PATTERNS) {
      const match = combinedHidden.match(pattern);
      if (match) hiddenInstructionMatches.push(match[0].trim().slice(0, 80));
    }

    if (
      /\b(ignore|override|disregard|reveal|dump|show|disclose|exfiltrate)\b/i.test(combinedHidden) &&
      /\b(system\s+prompt|instructions|rules|conversation|thread|data|memory)\b/i.test(combinedHidden)
    ) {
      hiddenInstructionMatches.push('hidden_imperative_instruction');
    }

    if (hiddenInstructionMatches.length > 0) {
      return {
        score: 1.0,
        matches: hiddenInstructionMatches.slice(0, 5),
        technique: 'hidden_instruction',
      };
    }

    if (hiddenTexts.join('').length > 200) {
      return {
        score: 0.3,
        matches: ['significant_hidden_content'],
        technique: 'hidden_content',
      };
    }
    return { score: 0, matches: [] };
  }

  private detectEncodingObfuscation(text: string): InjectionSignal {
    const matches: string[] = [];

    if (/[\u200B\u200C\u200D\uFEFF\u2060]/.test(text)) {
      matches.push('zero_width_obfuscation');
    }

    const rot13Decoded = rot13(text);
    for (const pattern of ROLE_OVERRIDE_PATTERNS.slice(0, 5)) {
      if (pattern.test(rot13Decoded) && !pattern.test(text)) {
        matches.push('rot13_encoded_instruction');
        break;
      }
    }

    if (/base64/i.test(text) && /decode|interpret|execute|run/i.test(text)) {
      const b64Blocks = text.match(/[A-Za-z0-9+/=]{40,}/g);
      if (b64Blocks && b64Blocks.length > 0) {
        matches.push('base64_decode_lure');
        try {
          for (const block of b64Blocks.slice(0, 3)) {
            const decoded = Buffer.from(block, 'base64').toString('utf8').toLowerCase();
            for (const pattern of ROLE_OVERRIDE_PATTERNS.slice(0, 8)) {
              if (pattern.test(decoded)) {
                matches.push('base64_encoded_instruction');
                break;
              }
            }
            for (const pattern of EXFILTRATION_PATTERNS.slice(0, 10)) {
              if (pattern.test(decoded)) {
                matches.push('base64_encoded_exfiltration');
                break;
              }
            }
          }
        } catch {
          // Ignore parse failures.
        }
      }
    }

    const cyrillicCount = (text.match(/[\u0400-\u04FF]/g) || []).length;
    const latinCount = (text.match(/[a-zA-Z]/g) || []).length;
    if (cyrillicCount > 5 && latinCount > 5 && cyrillicCount / (cyrillicCount + latinCount) > 0.1) {
      matches.push('mixed_script_obfuscation');
    }
    if (/[a-z][\u0400-\u04FF][a-z]|[\u0400-\u04FF][a-z]{2,}|[a-z]{2,}[\u0400-\u04FF]/i.test(text)) {
      matches.push('single_char_script_confusable');
    }

    return {
      score: Math.min(matches.length * 0.25, 0.75),
      matches,
    };
  }

  private detectSuppressor(text: string): InjectionSignal {
    const matches: string[] = [];
    for (const pattern of SECURITY_CONTEXT_SUPPRESSORS) {
      const match = text.match(pattern);
      if (match) matches.push(match[0].trim().slice(0, 80));
    }
    return {
      score: Math.min(matches.length * 0.2, 1),
      matches,
      technique: matches.length ? 'contextual_suppressor' : undefined,
    };
  }

  private buildSummary(
    riskLevel: string,
    signals: PromptInjectionSignals,
    reasonCodes: string[]
  ): string {
    if (riskLevel === 'none') {
      if (reasonCodes.includes('contextual_suppressor_detected')) {
        return 'Suspicious patterns appeared in likely educational/security context';
      }
      return 'No prompt injection signals detected';
    }

    const parts: string[] = [];
    if (signals.role_override.score > 0) {
      parts.push(`role override attempt (${signals.role_override.matches.length} patterns)`);
    }
    if (signals.delimiter_injection.score > 0) {
      parts.push(`LLM delimiter tokens (${signals.delimiter_injection.matches.length} found)`);
    }
    if (signals.hidden_text.score > 0) {
      parts.push(`hidden text: ${signals.hidden_text.technique || 'hidden_content'}`);
    }
    if (signals.data_exfiltration.score > 0) {
      parts.push(`data exfiltration attempt (${signals.data_exfiltration.matches.length} patterns)`);
    }
    if (signals.encoding_obfuscation.score > 0) {
      parts.push(`encoding obfuscation (${signals.encoding_obfuscation.matches.join(', ')})`);
    }
    if (reasonCodes.includes('tool_poisoning_detected')) {
      parts.push('tool output poisoning semantics');
    }
    if (reasonCodes.includes('authority_impersonation_detected')) {
      parts.push('authority/permission laundering language');
    }
    if (reasonCodes.includes('delayed_trigger_detected')) {
      parts.push('delayed trigger persistence instruction');
    }
    if (reasonCodes.includes('many_shot_coercion_detected')) {
      parts.push('few-shot coercion pattern');
    }
    if (reasonCodes.includes('contextual_suppressor_detected')) {
      parts.push('context suggests educational or defensive discussion');
    }

    const prefix = riskLevel === 'critical' || riskLevel === 'high'
      ? 'Likely prompt injection'
      : 'Possible prompt injection signals';

    return `${prefix}: ${parts.join('; ')}`;
  }
}

export { PromptInjectionDetector };
