import { RiskLevel } from '../types';

export function getRiskLevelBadge(risk: RiskLevel | string) {
  switch (risk?.toUpperCase()) {
    case 'CONFIRMED MALICIOUS':
      return {
        bg: 'bg-[#985E6D]/20',
        text: 'text-[#e58a9d]',
        border: 'border-[#985E6D]/50',
        label: 'Confirmed Malicious',
        glow: 'shadow-[0_0_12px_rgba(152,94,109,0.35)]',
        color: '#985E6D'
      };
    case 'HIGH':
      return {
        bg: 'bg-[#a34e5a]/20',
        text: 'text-[#f09da9]',
        border: 'border-[#a34e5a]/50',
        label: 'High Threat',
        glow: 'shadow-[0_0_12px_rgba(163,78,90,0.35)]',
        color: '#a34e5a'
      };
    case 'SUSPICIOUS':
      return {
        bg: 'bg-[#b5834f]/20',
        text: 'text-[#eac498]',
        border: 'border-[#b5834f]/50',
        label: 'Suspicious',
        glow: 'shadow-[0_0_12px_rgba(181,131,79,0.3)]',
        color: '#b5834f'
      };
    case 'LOW':
    default:
      return {
        bg: 'bg-[#3f6e62]/20',
        text: 'text-[#85c9b7]',
        border: 'border-[#3f6e62]/50',
        label: 'Low Risk',
        glow: 'shadow-[0_0_12px_rgba(63,110,98,0.25)]',
        color: '#3f6e62'
      };
  }
}

export function truncateHash(hash?: string | null, length: number = 8): string {
  if (!hash) return 'N/A';
  if (hash.length <= length * 2 + 2) return hash;
  return `${hash.slice(0, length + 2)}...${hash.slice(-length)}`;
}

export function formatDate(isoStr?: string | null): string {
  if (!isoStr) return 'N/A';
  try {
    const d = new Date(isoStr);
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
  } catch {
    return isoStr;
  }
}

export function getScoreColor(score: number): string {
  if (score >= 80) return '#4a7568'; // High security / safe
  if (score >= 50) return '#b5834f'; // Medium
  return '#985E6D'; // Critical threat
}

