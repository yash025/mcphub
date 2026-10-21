import type { CredentialSlot, ServerConfig } from '../types/index.js';

export class CredentialBindingError extends Error {}

// Runtime-only values must never become part of a serializable server configuration.
export const argumentCredentialBindings = new WeakMap<ServerConfig, Record<string, string>>();
const argumentSlotPattern = /\{\{args\.([A-Za-z_][A-Za-z0-9_]*)\}\}/g;

export const resolveCredentialArguments = (config: ServerConfig, args: string[]): string[] =>
  args.map((arg) => {
    if (arg.replace(argumentSlotPattern, '').includes('{{args.')) {
      throw new CredentialBindingError('Invalid args credential reference');
    }
    return arg.replace(argumentSlotPattern, (_reference, name: string) => {
      const value = argumentCredentialBindings.get(config)?.[name];
      if (value === undefined) throw new CredentialBindingError('Missing args credential binding');
      return value;
    });
  });

const urlSlotPattern = /\{\{url\.([A-Za-z_][A-Za-z0-9_]*)\}\}/g;
// One host label or path segment: no separators, scheme, port or `..`.
const urlSlotValuePattern = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$/;
const isUrlSafeValue = (value: unknown): value is string =>
  typeof value === 'string' && urlSlotValuePattern.test(value) && !value.includes('..');

export const isAllowedUrlSlotValue = (slot: CredentialSlot, value: unknown): value is string =>
  isUrlSafeValue(value) && !!slot.allowed?.includes(value);

export const hasUrlCredentialSlots = (config?: ServerConfig): boolean =>
  !!config?.credentialTemplate?.some((slot) => slot.target === 'url');

export const resolveCredentialUrl = (url: string, values: Record<string, string>): string =>
  url.replace(urlSlotPattern, (_reference, name: string) => {
    const value = values[name];
    if (value === undefined) throw new CredentialBindingError('Missing url credential binding');
    return value;
  });

const validateUrlSlot = (slot: CredentialSlot): void => {
  const { allowed } = slot;
  if (
    !Array.isArray(allowed) ||
    !allowed.length ||
    allowed.length > 256 ||
    !allowed.every(isUrlSafeValue) ||
    new Set(allowed).size !== allowed.length
  ) {
    throw new CredentialBindingError(
      'Invalid url credential slot: allowed must list 1 to 256 unique host labels or path segments',
    );
  }
};

// References and slots must match one-to-one, and the URL must stay plain http(s).
const validateUrlReferences = (config: ServerConfig, ids: Set<string>, slots: CredentialSlot[]) => {
  const urlSlots = slots.filter((slot) => slot.target === 'url');
  if (!urlSlots.length && !config.url?.includes('{{url.')) return;
  const referenced = new Set<string>();
  const sample = (config.url ?? '').replace(urlSlotPattern, (_reference, name: string) => {
    if (!ids.has(`url.${name}`))
      throw new CredentialBindingError('Unknown url credential reference');
    referenced.add(name);
    return 'slot';
  });
  if (sample.includes('{{url.'))
    throw new CredentialBindingError('Invalid url credential reference');
  if (urlSlots.some((slot) => !referenced.has(slot.name))) {
    throw new CredentialBindingError('Every url slot must be referenced in the server URL');
  }
  let parsed: URL | undefined;
  try {
    parsed = new URL(sample);
  } catch {
    parsed = undefined;
  }
  if (
    !parsed ||
    !['http:', 'https:'].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password
  ) {
    throw new CredentialBindingError(
      'url credential references may only fill host labels, path segments or query values',
    );
  }
};

export const hasCredentialTemplate = (config?: ServerConfig): boolean =>
  Array.isArray(config?.credentialTemplate) && config.credentialTemplate.length > 0;

export const hasPersonalAuthentication = (config?: ServerConfig): boolean =>
  hasCredentialTemplate(config) || config?.oauth?.identityMode === 'personal';

export const credentialSlotId = (slot: CredentialSlot): string => `${slot.target}.${slot.name}`;

export const validateCredentialTemplate = (config: ServerConfig): CredentialSlot[] | undefined => {
  const slots = config.credentialTemplate ?? [];
  if (!Array.isArray(slots) || slots.length > 32) {
    throw new CredentialBindingError('Credential template must contain at most 32 slots');
  }
  const stdio = config.type === 'stdio' || (!config.type && !!config.command && !config.url);
  const targets = stdio
    ? ['env', 'args']
    : config.type === 'openapi'
      ? ['headers']
      : ['headers', 'url'];
  const ids = new Set<string>();
  for (const slot of slots) {
    const keys =
      slot?.target === 'url' ? ['target', 'name', 'label', 'allowed'] : ['target', 'name', 'label'];
    if (
      !slot ||
      typeof slot !== 'object' ||
      Object.keys(slot).some((key) => !keys.includes(key)) ||
      !targets.includes(slot.target) ||
      typeof slot.name !== 'string' ||
      slot.name.length > 128 ||
      !(
        slot.target === 'headers' ? /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/ : /^[A-Za-z_][A-Za-z0-9_]*$/
      ).test(slot.name) ||
      ['__proto__', 'constructor', 'prototype'].includes(slot.name.toLowerCase()) ||
      (slot.label !== undefined && (typeof slot.label !== 'string' || slot.label.length > 200))
    ) {
      throw new CredentialBindingError(
        'Invalid credential slot: use env or args for stdio, or headers or url for HTTP servers',
      );
    }
    if (slot.target === 'url') validateUrlSlot(slot);
    const id = `${slot.target}.${slot.target === 'headers' ? slot.name.toLowerCase() : slot.name}`;
    if (ids.has(id)) throw new CredentialBindingError('Duplicate credential slot');
    ids.add(id);
  }
  validateUrlReferences(config, ids, slots);
  const referencedArgs = new Set<string>();
  for (const arg of config.args ?? []) {
    if (typeof arg !== 'string') throw new CredentialBindingError('Arguments must be strings');
    const remainder = arg.replace(argumentSlotPattern, (_reference, name: string) => {
      if (!stdio || !ids.has(`args.${name}`)) {
        throw new CredentialBindingError('Unknown args credential reference');
      }
      referencedArgs.add(name);
      return '';
    });
    if (remainder.includes('{{args.')) {
      throw new CredentialBindingError('Invalid args credential reference');
    }
  }
  if (slots.some((slot) => slot.target === 'args' && !referencedArgs.has(slot.name))) {
    throw new CredentialBindingError('Every args slot must be referenced in arguments');
  }
  // Older dashboard versions persisted the default identity label even when
  // OAuth was never configured. Only that bare shared label is harmless.
  const hasOAuthConfig =
    config.oauth &&
    Object.keys(config.oauth).some(
      (key) => key !== 'identityMode' || config.oauth?.identityMode !== 'shared',
    );
  if (slots.length && hasOAuthConfig) {
    throw new CredentialBindingError(
      'Per-user credential slots cannot be combined with shared OAuth',
    );
  }
  return slots.length
    ? slots.map(({ target, name, label, allowed }) => ({
        target,
        name,
        ...(label ? { label } : {}),
        ...(allowed ? { allowed: [...allowed] } : {}),
      }))
    : undefined;
};
