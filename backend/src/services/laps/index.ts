import crypto from 'crypto';
import { db } from '../../db/index.js';
import { resolveEffectiveDevicePolicy } from '../policy/index.js';
import { encryptVaultSecret, decryptVaultSecret } from '../vault/index.js';
import { meshBridge } from '../meshcentral/index.js';

// High-entropy unambiguous passphrase dictionary (512 distinct roots x 2 forms = >9 bits/word)
const BASE_WORDS = [
  'Acorn', 'Admiral', 'Aegis', 'Alabaster', 'Alchemy', 'Almanac', 'Alpine', 'Amber',
  'Amethyst', 'Anchor', 'Anvil', 'Apex', 'Apollo', 'Aqueduct', 'Arbor', 'Arcade',
  'Archery', 'Arctic', 'Argon', 'Armada', 'Arrow', 'Artisan', 'Asphalt', 'Asteroid',
  'Atlas', 'Atrium', 'Aurora', 'Avalanche', 'Aviator', 'Axiom', 'Azimuth', 'Azure',
  'Badger', 'Balsa', 'Bamboo', 'Banner', 'Baritone', 'Barium', 'Barley', 'Basalt',
  'Bastion', 'Beacon', 'Belfry', 'Beryl', 'Bison', 'Bitumen', 'Blizzard', 'Blossom',
  'Bluejay', 'Bobcat', 'Bolero', 'Bonfire', 'Bonsai', 'Boron', 'Boulder', 'Bramble',
  'Bravo', 'Breeze', 'Brigade', 'Brimstone', 'Bronze', 'Buckler', 'Bulwark', 'Butte',
  'Cabana', 'Cadence', 'Cairn', 'Calcite', 'Caliber', 'Calypso', 'Camber', ' Cameo'.trim(),
  'Canopy', 'Canyon', 'Capstan', 'Caravan', 'Carbon', 'Cardinal', 'Caribou', 'Cascade',
  'Cashmere', 'Citadel', 'Catalyst', 'Cavern', 'Cedar', 'Celadon', 'Centaur', 'Ceramic',
  'Cesium', 'Chalet', 'Chalice', 'Chamois', 'Channel', 'Charger', 'Chariot', 'Charter',
  'Chevron', 'Chimera', 'Chisel', 'Chrome', 'Chronicle', 'Cinder', 'Cipher', 'Cirrus',
  'Citrine', ' Clarion'.trim(), 'Cleaver', 'Clover', 'Cobalt', 'Cobble', 'Comet', 'Compass',
  'Condor', 'Conduit', 'Conifer', 'Consul', 'Contour', 'Copper', 'Coral', 'Cordova',
  'Coronet', 'Corsair', 'Cortex', 'Corvette', 'Cosmos', 'Cougar', 'Crater', 'Crescendo',
  'Crimson', ' Crucible'.trim(), 'Crystal', 'Culvert', 'Cumulus', 'Curator', 'Current', 'Cutlass',
  'Cyanide', 'Cyclone', 'Cypress', 'Dagger', 'Dahlia', 'Dakota', 'Damask', 'Dapper',
  'Daybreak', 'Decibel', 'Defiant', 'Delta', 'Derrick', 'Desperado', 'Diadem', 'Diagram',
  'Diamond', 'Diffuse', 'Digital', 'Diode', 'Diorama', 'Dipper', 'Dolomite', 'Dolphin',
  'Domino', 'Dorado', 'Doublet', 'Dragon', 'Drifter', 'Droplet', 'Druid', 'Dryad',
  'Ductile', 'Dune', 'Dynamo', 'Eagle', 'Echelon', 'Eclipse', 'Edict', 'Edifice',
  'Egret', 'Ejector', 'Electra', 'Element', 'Elixir', 'Embassy', 'Ember', 'Emerald',
  'Eminence', 'Emperor', 'Empire', 'Enclave', 'Encore', 'Endurance', 'Enigma', 'Ensign',
  'Entropy', 'Envoy', 'Eon', 'Epicenter', 'Epoch', 'Equinox', 'Erudite', 'Escarp',
  'Estuary', 'Ether', 'Eulogy', 'Eureka', 'Everest', 'Excalibur', 'Exodus', 'Expanse',
  'Express', 'Facet', 'Falcon', 'Fathom', 'Feldspar', 'Fennel', 'Ferret', 'Ferrite',
  'Festival', 'Fidelis', 'Filament', 'Finch', 'Firefly', 'Fissure', 'Fjord', 'Flagon',
  'Flamingo', 'Flint', 'Flotilla', 'Fluorite', 'Flywheel', 'Foliage', 'Forage', 'Foreman',
  'Forge', 'Formula', 'Fortress', 'Fossil', 'Foundry', 'Foxhound', 'Fractal', 'Fragment',
  'Fresco', 'Frigate', 'Frontier', 'Fulcrum', 'Fumarole', 'Furnace', 'Fusion', 'Gabbro',
  'Galena', 'Galleon', 'Gallium', 'Gambit', 'Gamma', 'Gannet', 'Garnet', 'Garrison',
  'Gateway', 'Gazelle', 'Geyser', 'Ginkgo', 'Glacier', 'Glider', 'Glimmer', 'Gondola',
  'Gopher', 'Gossamer', 'Granite', 'Graphite', 'Gravity', 'Grebe', 'Griffin', 'Grotto',
  'Gryphon', 'Guardian', 'Gypsum', 'Habitat', 'Halberd', 'Halcyon', 'Halite', 'Hammer',
  'Hammock', 'Harbinger', 'Harbor', 'Harmony', 'Harpoon', 'Harvest', 'Hawkeye', 'Hawthorn',
  'Hazard', 'Heather', 'Hectare', 'Helium', 'Helix', 'Helmet', 'Hemlock', 'Herald',
  'Hercules', 'Heritage', 'Hermit', 'Heron', 'Hickory', 'Highland', 'Horizon', 'Hornet',
  'Hospitaller', 'Howitzer', 'Hubble', 'Humidor', 'Hunter', 'Huron', 'Husky', ' Hyacinth'.trim(),
  'Hydra', 'Hydrant', 'Hydrogen', 'Hyperion', 'Ibex', 'Iceberg', 'Icicle', 'Icon',
  'Igloo', 'Ignite', 'Iguana', 'Illumina', 'Impact', 'Impala', 'Imperial', 'Impulse',
  'Incisor', 'Indigo', 'Inertia', 'Inferno', 'Infinity', 'Ingot', 'Inlet', 'Insignia',
  'Ion', 'Iridium', 'Ironclad', 'Island', 'Isotope', 'Isthmus', 'Ivory', 'Jacinth',
  'Jackal', 'Jadeite', 'Jaguar', 'Jasper', 'Javelin', 'Jericho', 'Jester', 'Jetstream',
  'Jigsaw', 'Journal', 'Jubilee', 'Juggernaut', 'Junction', 'Juniper', 'Jupiter', 'Kestrel',
  'Keystone', 'Kilowatt', 'Kinetic', 'Kingdom', 'Kingfisher', 'Krypton', 'Labyrinth', 'Lacquer',
  'Lagoon', 'Lancer', 'Lantern', 'Lapidary', 'Lapis', 'Lariat', 'Lattice', 'Laurel',
  'Lava', 'Lavender', 'Ledger', 'Legacy', 'Legend', 'Lemming', 'Leopard', 'Lexicon',
  'Liberty', 'Lighthouse', 'Lignite', 'Limestone', 'Linchpin', 'Lithium', 'Lodestar', 'Lodestone',
  'Longbow', 'Lookout', 'Lotus', 'Lumen', 'Lunar', 'Lupine', 'Lustre', 'Lynx',
  'Macaw', 'Machete', 'Maestro', 'Magenta', 'Magma', 'Magnesia', 'Magnet', 'Magnolia',
  'Mahogany', 'Majesty', 'Malachite', 'Mallard', 'Mammoth', 'Mandarin', 'Mandolin', 'Manganese',
  'Manifold', 'Mantis', 'Mantle', 'maple', 'Marathon', 'Marble', 'Marigold', 'Mariner',
  'Marlin', 'Marmot', 'Marquee', 'Marshal', 'Mastiff', 'Matrix', 'Maverick', 'Meadow',
  'Medallion', 'Mega', 'Melon', 'Memento', 'Mercury', 'Meridian', 'Merlin', 'Mesa',
  'Meteor', 'Mica', 'Micro', 'Midway', 'Millennium', 'Minaret', 'Mineral', 'Minerva',
  'Mirage', 'Mistral', 'Mithril', 'Mizzen', 'Modular', 'Molecule', 'Molybdenum', 'Monarch',
  'Monitor', 'Monolith', 'Monsoon', 'Montage', 'Monument', 'Moraine', 'Mosaic', 'Mountain',
  'Mulberry', 'Mustang', 'Myriad', 'Mystic', 'Nadir', 'Narwhal', 'Nautilus', 'Navigator',
  'Nebula', 'Nectar', 'Neodymium', 'Neon', 'Neptune', 'Nettle', 'Neutron', 'Nexus',
  'Niagara', 'Nickel', 'Nimbus', 'Niobium', 'Nitrogen', 'Noble', 'Nomad', 'Nordic',
  'Nova', 'Nozzle', 'Nucleus', 'Nugget', 'Nutmeg', 'Oakwood', 'Oasis', 'Obelisk',
  'Obsidian', 'Octagon', 'Octane', 'Octave', 'Odyssey', 'Ocelot', 'Ohm', 'Olivine',
  'Olympus', 'Omega', 'Onyx', 'Opal', 'Oracle', 'Orbit', 'Orchard', 'Orchid',
  ' Oregano'.trim(), 'Oriole', 'Orion', 'Osprey', ' Osmium'.trim(), 'Otter', 'Outpost', 'Overland'
];

export function sanitizeLapsAccountName(rawName?: string | null): string {
  const cleaned = String(rawName || '')
    .replace(/[^a-zA-Z0-9._-]/g, '')
    .slice(0, 20);
  return cleaned || 'LocalAdmin';
}

export interface LapsCredential {
  deviceId: string;
  accountName: string;
  previousAccountName?: string | null;
  password?: string;
  previousPassword?: string | null;
  passwordMode?: 'random' | 'passphrase' | 'static';
  autoCreateAccount?: boolean;
  sid500BuiltinDisabled?: boolean;
  cleanupOldAccountAction?: 'disable' | 'delete' | 'keep';
  expiresAt: string;
  lastRotated: string;
  autoRotateScheduled?: boolean;
  rotationPendingOnline?: boolean;
  pendingRotationReason?: string | null;
  pendingAccountName?: string | null;
  provisioned?: boolean;
  verifiedOnEndpoint?: boolean;
  error?: string;
  pushOutput?: string;
  rotationStatus?:
    | 'active'
    | 'rotated_live'
    | 'deferred_until_online'
    | 'skipped_pending_offboard'
    | 'not_provisioned'
    | 'push_failed';
}

const MASK = '••••••••••••••••';

export function getLapsCredential(
  deviceId: string,
  reveal = false,
  options?: { actorUsername?: string; skipAccessExpiryMutation?: boolean }
): LapsCredential | null {
  const deviceExists = db.prepare('SELECT id, status, lifecycle_state FROM devices WHERE id = ?').get(deviceId) as
    | { id: string; status?: string; lifecycle_state?: string }
    | undefined;
  if (!deviceExists) {
    return null;
  }

  const row = db.prepare('SELECT * FROM laps_vault WHERE device_id = ?').get(deviceId) as any;
  if (!row) {
    if (deviceExists.lifecycle_state && deviceExists.lifecycle_state !== 'active') {
      return null;
    }
    let unprovisionedPolicy: any = null;
    try {
      unprovisionedPolicy = resolveEffectiveDevicePolicy(deviceId);
    } catch {}
    const accountName = sanitizeLapsAccountName(unprovisionedPolicy?.lapsAccountName || 'LocalAdmin');
    return {
      deviceId,
      accountName,
      passwordMode: unprovisionedPolicy?.lapsPasswordMode || 'random',
      autoCreateAccount: unprovisionedPolicy?.lapsAutoCreateAccount ?? true,
      sid500BuiltinDisabled: unprovisionedPolicy?.lapsDisableBuiltinSid500Admin !== false,
      cleanupOldAccountAction: unprovisionedPolicy?.lapsCleanupOldAccountOnRename || 'disable',
      expiresAt: '',
      lastRotated: '',
      autoRotateScheduled: Boolean(unprovisionedPolicy?.lapsAutoRotateDays),
      rotationPendingOnline: false,
      pendingRotationReason:
        deviceExists.status === 'online'
          ? 'No LAPS password has been provisioned on this endpoint yet. Click "Provision Account & Set Password Now" to push and verify a local admin password.'
          : 'No LAPS password has been provisioned on this endpoint yet, and the device is currently offline.',
      provisioned: false,
      verifiedOnEndpoint: false,
      rotationStatus: 'not_provisioned'
    };
  }

  let policy: any = null;
  try {
    policy = resolveEffectiveDevicePolicy(deviceId);
  } catch {}

  let decryptedPassword = '';
  let decryptedPreviousPassword = '';
  let autoRotateScheduled = false;

  if (reveal) {
    decryptedPassword = decryptVaultSecret(row.encrypted_password);
    decryptedPreviousPassword = decryptVaultSecret(row.previous_encrypted_password);

    if (!options?.skipAccessExpiryMutation) {
      let graceNote = 'Post-access auto-rotation disabled by policy.';
      if (
        policy &&
        policy.lapsRotateOnAccess &&
        policy.lapsPasswordMode !== 'static' &&
        deviceExists.lifecycle_state === 'active'
      ) {
        const graceHours = Math.max(1, Number(policy.lapsPostAccessGraceHours || 2));
        const candidateMs = Date.now() + graceHours * 3600 * 1000;
        const currentMs = row.expires_at ? new Date(row.expires_at).getTime() : candidateMs;
        // Never extend an already-sooner expiry window!
        const effectiveMs = Number.isNaN(currentMs) ? candidateMs : Math.min(currentMs, candidateMs);
        const newExpiry = new Date(effectiveMs).toISOString();
        db.prepare('UPDATE laps_vault SET expires_at = ? WHERE device_id = ?').run(newExpiry, deviceId);
        row.expires_at = newExpiry;
        autoRotateScheduled = true;
        graceNote = `Auto-rotation grace window armed (${graceHours}h max, expires ${newExpiry}).`;
      }

      // UNCONDITIONALLY record LAPS Ephemeral Access audit log whenever a plaintext secret is revealed!
      db.prepare(`
        INSERT INTO audit_logs (id, username, device_id, action, details)
        VALUES (?, ?, ?, 'LAPS Ephemeral Access', ?)
      `).run(
        `aud-laps-${crypto.randomUUID()}`,
        options?.actorUsername || 'technician',
        deviceId,
        `Revealed LAPS secret for '${row.account_name}'. ${graceNote}`
      );
    }
  }

  const isExpiredWhileOffline =
    deviceExists.status !== 'online' &&
    deviceExists.lifecycle_state === 'active' &&
    row.expires_at &&
    new Date(row.expires_at).getTime() <= Date.now();

  const rotationPendingOnline = Boolean(row.rotation_pending_online || isExpiredWhileOffline);
  const pendingReason =
    row.pending_rotation_reason ||
    (isExpiredWhileOffline
      ? 'Scheduled rotation due while endpoint is offline — current password preserved until agent is back online'
      : null);

  return {
    deviceId: row.device_id,
    accountName: row.account_name,
    previousAccountName: row.previous_account_name || null,
    password: reveal ? decryptedPassword : MASK,
    previousPassword: reveal
      ? decryptedPreviousPassword || null
      : row.previous_encrypted_password
      ? MASK
      : null,
    passwordMode: policy?.lapsPasswordMode || 'random',
    autoCreateAccount: policy?.lapsAutoCreateAccount ?? true,
    sid500BuiltinDisabled: Boolean(policy?.lapsDisableBuiltinSid500Admin ?? row.sid500_builtin_disabled ?? 1),
    cleanupOldAccountAction: policy?.lapsCleanupOldAccountOnRename || 'disable',
    expiresAt: row.expires_at,
    lastRotated: row.last_rotated,
    autoRotateScheduled,
    rotationPendingOnline,
    pendingRotationReason: pendingReason,
    pendingAccountName: row.pending_account_name || null,
    provisioned: true,
    verifiedOnEndpoint: !rotationPendingOnline,
    rotationStatus:
      deviceExists.lifecycle_state === 'pending_offboard'
        ? 'skipped_pending_offboard'
        : rotationPendingOnline
        ? 'deferred_until_online'
        : 'active'
  };
}

function containsAccountNameSubstring(secret: string, accountName?: string): boolean {
  const cleanAcct = (accountName || '').trim().toLowerCase();
  if (!cleanAcct) return false;
  return secret.toLowerCase().includes(cleanAcct);
}

function generateNewLapsSecret(policy: any, accountName?: string): string {
  const passwordMode: 'random' | 'passphrase' | 'static' = policy?.lapsPasswordMode || 'random';
  const passLength = Math.max(14, Math.min(64, Number(policy?.lapsPasswordLength || 20)));
  const complexity = policy?.lapsComplexity || 'alphanumeric_symbols';

  const staticConfigured = policy?.lapsStaticPasswordRaw
    ? decryptVaultSecret(policy.lapsStaticPasswordRaw)
    : '';

  if (passwordMode === 'static' && staticConfigured && !containsAccountNameSubstring(staticConfigured, accountName)) {
    return staticConfigured;
  }

  if (passwordMode === 'passphrase') {
    const wordCount = Math.max(4, Math.min(8, Number(policy?.lapsPassphraseWords || 5)));
    const sep = String(policy?.lapsPassphraseSeparator || '-').slice(0, 2) || '-';
    const cleanAcctLower = (accountName || '').trim().toLowerCase();
    const safePool = cleanAcctLower
      ? BASE_WORDS.filter((w) => !w.toLowerCase().includes(cleanAcctLower))
      : BASE_WORDS;
    const pool = safePool.length >= 16 ? safePool : BASE_WORDS;

    for (let attempt = 0; attempt < 25; attempt++) {
      const picked: string[] = [];
      for (let i = 0; i < wordCount; i++) {
        picked.push(pool[crypto.randomInt(0, pool.length)]);
      }
      const suffixNum = crypto.randomInt(100, 999);
      const symbols = '!@#$%^&*';
      const suffixSym = symbols[crypto.randomInt(0, symbols.length)];
      const candidate = `${picked.join(sep)}${sep}${suffixNum}${suffixSym}`;
      if (!containsAccountNameSubstring(candidate, accountName)) {
        return candidate;
      }
    }
  }

  let uppers = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  let lowers = 'abcdefghijkmnopqrstuvwxyz';
  let digits = '23456789';
  let symbols = '';

  if (complexity === 'alphanumeric') {
    symbols = '';
  } else if (complexity === 'ascii_printable') {
    uppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    lowers = 'abcdefghijklmnopqrstuvwxyz';
    digits = '0123456789';
    symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  } else {
    symbols = '!@#$%^&*';
  }

  // If accountName is a single character, exclude it from character classes so we never include it
  const cleanAcctLower = (accountName || '').trim().toLowerCase();
  if (cleanAcctLower.length === 1) {
    uppers = [...uppers].filter((c) => c.toLowerCase() !== cleanAcctLower).join('') || 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    lowers = [...lowers].filter((c) => c.toLowerCase() !== cleanAcctLower).join('') || 'abcdefghijkmnopqrstuvwxyz';
    digits = [...digits].filter((c) => c.toLowerCase() !== cleanAcctLower).join('') || '23456789';
    if (symbols) {
      symbols = [...symbols].filter((c) => c.toLowerCase() !== cleanAcctLower).join('') || '!@#$%^&*';
    }
  }

  const fullCharset = `${uppers}${lowers}${digits}${symbols}`;

  for (let attempt = 0; attempt < 50; attempt++) {
    const chars: string[] = [
      uppers[crypto.randomInt(0, uppers.length)],
      lowers[crypto.randomInt(0, lowers.length)],
      digits[crypto.randomInt(0, digits.length)]
    ];
    if (symbols.length > 0) {
      chars.push(symbols[crypto.randomInt(0, symbols.length)]);
    }
    while (chars.length < passLength) {
      chars.push(fullCharset[crypto.randomInt(0, fullCharset.length)]);
    }
    for (let i = chars.length - 1; i > 0; i--) {
      const j = crypto.randomInt(0, i + 1);
      const tmp = chars[i];
      chars[i] = chars[j];
      chars[j] = tmp;
    }
    const candidate = chars.join('');
    if (!containsAccountNameSubstring(candidate, accountName)) {
      return candidate;
    }
  }

  // Fallback deterministic scrub if accountName somehow collided 50 times
  throw new Error('Unable to generate compliant LAPS password that excludes account name.');
}

export async function rotateLapsPasswordVerifiedAsync(
  deviceId: string,
  options?: {
    reveal?: boolean;
    actorUsername?: string;
    forceFinalArchiveSnapshot?: boolean;
  }
): Promise<LapsCredential> {
  const device = db
    .prepare('SELECT hostname, status, lifecycle_state, mesh_node_id, agent_auth_token FROM devices WHERE id = ?')
    .get(deviceId) as any;
  if (!device) throw new Error(`Device ${deviceId} not found`);

  if (device.lifecycle_state && device.lifecycle_state !== 'active' && !options?.forceFinalArchiveSnapshot) {
    return rotateLapsPassword(deviceId, options);
  }

  const existingRow = db.prepare('SELECT * FROM laps_vault WHERE device_id = ?').get(deviceId) as any;

  let policy: any = null;
  try {
    policy = resolveEffectiveDevicePolicy(deviceId);
  } catch {}

  const accountName = sanitizeLapsAccountName(policy?.lapsAccountName || 'LocalAdmin');
  const autoCreateAccount = policy?.lapsAutoCreateAccount ?? true;
  const sid500Disabled = policy?.lapsDisableBuiltinSid500Admin !== false ? 1 : 0;
  const cleanupAction: 'disable' | 'delete' | 'keep' = policy?.lapsCleanupOldAccountOnRename || 'disable';

  const buildUnprovisionedResult = (
    rotationStatus: 'deferred_until_online' | 'push_failed',
    reason: string,
    pushOutput?: string
  ): LapsCredential => ({
    deviceId,
    accountName,
    passwordMode: policy?.lapsPasswordMode || 'random',
    autoCreateAccount,
    sid500BuiltinDisabled: Boolean(sid500Disabled),
    cleanupOldAccountAction: cleanupAction,
    expiresAt: '',
    lastRotated: '',
    autoRotateScheduled: Boolean(policy?.lapsAutoRotateDays),
    rotationPendingOnline: rotationStatus === 'deferred_until_online',
    pendingRotationReason: reason,
    error: reason,
    pushOutput,
    provisioned: false,
    verifiedOnEndpoint: false,
    rotationStatus
  });

  if (device.status !== 'online') {
    if (!existingRow && !options?.forceFinalArchiveSnapshot) {
      return buildUnprovisionedResult(
        'deferred_until_online',
        `Device ${device.hostname} is offline. Bring it online before provisioning LAPS so Vitrine can create/update '${accountName}' and verify the password on the endpoint.`
      );
    }
    return rotateLapsPassword(deviceId, options);
  }

  const candidatePass = generateNewLapsSecret(policy, accountName);

  // Verify live MeshCentral execution BEFORE committing any password into laps_vault!
  // Never allow offline or companion-only `agent_tasks` queue fallback to change endpoint password to a discarded credential (C-7).
  const hasLiveMeshTunnel = Boolean(meshBridge.getStatus().connected && device.mesh_node_id);
  if (!hasLiveMeshTunnel) {
    const noTunnelMsg = `No live MeshCentral relay tunnel is connected for ${device.hostname}; cannot verify local account '${accountName}' on the endpoint.`;
    if (existingRow) {
      db.prepare(`
        UPDATE laps_vault
        SET rotation_pending_online = 1, pending_rotation_reason = ?, pending_account_name = ?
        WHERE device_id = ?
      `).run(noTunnelMsg, accountName, deviceId);
      const preserved = getLapsCredential(deviceId, Boolean(options?.reveal), {
        actorUsername: options?.actorUsername,
        skipAccessExpiryMutation: true
      })!;
      return { ...preserved, rotationPendingOnline: true, verifiedOnEndpoint: false, error: noTunnelMsg };
    }
    return buildUnprovisionedResult('push_failed', noTunnelMsg);
  }

  const pushRes = await meshBridge.verifyAndPushLapsCredentialToNode(deviceId, {
    accountName,
    password: candidatePass,
    autoCreateAccount,
    disableSid500: Boolean(sid500Disabled),
    previousAccountName:
      existingRow?.account_name && existingRow.account_name !== accountName ? existingRow.account_name : null,
    cleanupOldAccountAction: cleanupAction
  });

  const verifiedLive = Boolean(pushRes.delivered && pushRes.verifiedLive !== false);
  if (!verifiedLive) {
    const snippet = (pushRes.output || 'No verification output returned by endpoint agent').slice(0, 180);
    if (existingRow) {
      const deferReason = `Deferred rotation on ${device.hostname}: Live agent verification did not succeed (${snippet}). Current vaulted password preserved to prevent lockout.`;
      db.prepare(`
        UPDATE laps_vault
        SET rotation_pending_online = 1, pending_rotation_reason = ?, pending_account_name = ?
        WHERE device_id = ?
      `).run(deferReason, accountName, deviceId);
      const preserved = getLapsCredential(deviceId, Boolean(options?.reveal), {
        actorUsername: options?.actorUsername,
        skipAccessExpiryMutation: true
      })!;
      return {
        ...preserved,
        verifiedOnEndpoint: false,
        error: deferReason,
        pushOutput: pushRes.output
      };
    }
    return buildUnprovisionedResult(
      'push_failed',
      `Failed to verify local admin account '${accountName}' on ${device.hostname}: ${snippet}`,
      pushRes.output
    );
  }

  const committed = rotateLapsPassword(deviceId, {
    ...options,
    preVerifiedPlaintextPassword: candidatePass
  });
  return {
    ...committed,
    provisioned: true,
    verifiedOnEndpoint: true,
    pushOutput: pushRes.output,
    rotationStatus: 'rotated_live'
  };
}

export function rotateLapsPassword(
  deviceId: string,
  options?: {
    forceFinalArchiveSnapshot?: boolean;
    forceInitialProvision?: boolean;
    reveal?: boolean;
    actorUsername?: string;
    preVerifiedPlaintextPassword?: string;
  }
): LapsCredential {
  const shouldReveal = Boolean(options?.reveal);
  const actor = options?.actorUsername || 'system';
  const isPreVerified = Boolean(options?.preVerifiedPlaintextPassword);

  let policy: any = null;
  try {
    policy = resolveEffectiveDevicePolicy(deviceId);
  } catch {}

  const device = db
    .prepare('SELECT hostname, status, lifecycle_state, os_type, mesh_node_id FROM devices WHERE id = ?')
    .get(deviceId) as
    | { hostname: string; status: string; lifecycle_state?: string; os_type?: string; mesh_node_id?: string }
    | undefined;

  if (!device) {
    throw new Error(`Device ${deviceId} not found`);
  }

  const existingRow = db.prepare('SELECT * FROM laps_vault WHERE device_id = ?').get(deviceId) as any;

  const accountName = sanitizeLapsAccountName(policy?.lapsAccountName || 'LocalAdmin');
  const passwordMode: 'random' | 'passphrase' | 'static' = policy?.lapsPasswordMode || 'random';
  const rotationDays = policy?.lapsRotationDays ?? 30;
  const autoCreateAccount = policy?.lapsAutoCreateAccount ?? true;
  const sid500Disabled = policy?.lapsDisableBuiltinSid500Admin !== false ? 1 : 0;
  const cleanupAction: 'disable' | 'delete' | 'keep' = policy?.lapsCleanupOldAccountOnRename || 'disable';

  // SAFETY GUARDRAIL #1: Never provision, rotate, or overwrite credentials if device lifecycle_state !== 'active'
  if (
    !isPreVerified &&
    device.lifecycle_state &&
    device.lifecycle_state !== 'active' &&
    !options?.forceFinalArchiveSnapshot
  ) {
    const skipReason =
      device.lifecycle_state === 'pending_offboard'
        ? 'Skipped scheduled/manual rotation: Endpoint has a pending offboarding queued. Current password preserved to prevent lockout.'
        : `Skipped provisioning/rotation: Endpoint lifecycle_state is '${device.lifecycle_state}'. Historical state preserved.`;

    if (existingRow) {
      db.prepare(`
        UPDATE laps_vault
        SET rotation_pending_online = 0, pending_rotation_reason = ?
        WHERE device_id = ?
      `).run(skipReason, deviceId);
    }

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'LAPS Rotation Skipped (Offboard Guard)', ?)
    `).run(`aud-laps-skip-${crypto.randomUUID()}`, actor, deviceId, skipReason);

    const nowIso = new Date().toISOString();
    return {
      deviceId,
      accountName: existingRow?.account_name || accountName,
      previousAccountName: existingRow?.previous_account_name || null,
      password: shouldReveal
        ? existingRow
          ? decryptVaultSecret(existingRow.encrypted_password)
          : ''
        : MASK,
      previousPassword: shouldReveal
        ? existingRow
          ? decryptVaultSecret(existingRow.previous_encrypted_password) || null
          : null
        : existingRow?.previous_encrypted_password
        ? MASK
        : null,
      passwordMode,
      autoCreateAccount,
      sid500BuiltinDisabled: Boolean(sid500Disabled),
      cleanupOldAccountAction: cleanupAction,
      expiresAt: existingRow?.expires_at || nowIso,
      lastRotated: existingRow?.last_rotated || nowIso,
      autoRotateScheduled: false,
      rotationPendingOnline: false,
      pendingRotationReason: skipReason,
      pendingAccountName: null,
      rotationStatus: 'skipped_pending_offboard'
    };
  }

  // SAFETY GUARDRAIL #2: If device is OFFLINE, NEVER overwrite an existing vaulted password in Vitrine!
  if (!isPreVerified && existingRow && device.status !== 'online' && !options?.forceFinalArchiveSnapshot) {
    const deferReason = `Deferred until ${device.hostname} returns online: Current vaulted password ('${existingRow.account_name}') is preserved in Vitrine so technicians are never locked out while the machine is offline.`;
    db.prepare(`
      UPDATE laps_vault
      SET rotation_pending_online = 1,
          pending_rotation_reason = ?,
          pending_account_name = ?
      WHERE device_id = ?
    `).run(deferReason, accountName, deviceId);

    db.prepare(`
      INSERT INTO audit_logs (id, username, device_id, action, details)
      VALUES (?, ?, ?, 'LAPS Rotation Deferred (Offline Lockout Guard)', ?)
    `).run(`aud-laps-defer-${crypto.randomUUID()}`, actor, deviceId, deferReason);

    return {
      deviceId,
      accountName: existingRow.account_name,
      previousAccountName: existingRow.previous_account_name || null,
      password: shouldReveal ? decryptVaultSecret(existingRow.encrypted_password) : MASK,
      previousPassword: shouldReveal
        ? decryptVaultSecret(existingRow.previous_encrypted_password) || null
        : existingRow.previous_encrypted_password
        ? MASK
        : null,
      passwordMode,
      autoCreateAccount,
      sid500BuiltinDisabled: Boolean(sid500Disabled),
      cleanupOldAccountAction: cleanupAction,
      expiresAt: existingRow.expires_at,
      lastRotated: existingRow.last_rotated,
      autoRotateScheduled: false,
      rotationPendingOnline: true,
      pendingRotationReason: deferReason,
      pendingAccountName: accountName !== existingRow.account_name ? accountName : null,
      rotationStatus: 'deferred_until_online'
    };
  }

  const newPass = options?.preVerifiedPlaintextPassword || generateNewLapsSecret(policy, accountName);
  const previousAccount = existingRow?.account_name || null;
  const previousEncrypted = existingRow?.encrypted_password || null;
  const previousIv = existingRow?.iv || null;

  // SAFETY GUARDRAIL #3: Synchronous rotateLapsPassword without pre-verification must NEVER overwrite
  // an existing vaulted credential or claim live verification on an unverified/companion-only endpoint (C-7).
  const pushedSynchronously = isPreVerified;
  if (!isPreVerified && device.status === 'online') {
    if (existingRow) {
      const deferReason = `Deferred rotation on ${device.hostname}: Live MeshCentral verification is required before rotating vaulted password.`;
      db.prepare(`
        UPDATE laps_vault
        SET rotation_pending_online = 1,
            pending_rotation_reason = ?,
            pending_account_name = ?
        WHERE device_id = ?
      `).run(deferReason, accountName, deviceId);

      db.prepare(`
        INSERT INTO audit_logs (id, username, device_id, action, details)
        VALUES (?, ?, ?, 'LAPS Rotation Deferred (Unverified Tunnel Guard)', ?)
      `).run(`aud-laps-defer-${crypto.randomUUID()}`, actor, deviceId, deferReason);

      return {
        deviceId,
        accountName: existingRow.account_name,
        previousAccountName: existingRow.previous_account_name || null,
        password: shouldReveal ? decryptVaultSecret(existingRow.encrypted_password) : MASK,
        previousPassword: shouldReveal
          ? decryptVaultSecret(existingRow.previous_encrypted_password) || null
          : existingRow.previous_encrypted_password
          ? MASK
          : null,
        passwordMode,
        autoCreateAccount,
        sid500BuiltinDisabled: Boolean(sid500Disabled),
        cleanupOldAccountAction: cleanupAction,
        expiresAt: existingRow.expires_at,
        lastRotated: existingRow.last_rotated,
        autoRotateScheduled: false,
        rotationPendingOnline: true,
        pendingRotationReason: deferReason,
        pendingAccountName: accountName !== existingRow.account_name ? accountName : null,
        rotationStatus: 'deferred_until_online'
      };
    }
  }

  // Initial seed when offline or without live tunnel push: mark rotation_pending_online = 1
  const pendingOnlineFlag = !pushedSynchronously && !options?.forceFinalArchiveSnapshot ? 1 : 0;
  const pendingOnlineReason = pendingOnlineFlag
    ? `Initial LAPS credential seeded while ${device.hostname} has no verified live tunnel; queued for push upon online check-in.`
    : null;

  const encryptedPayload = encryptVaultSecret(newPass);
  const ivMarker = encryptedPayload.split(':')[2] || '';

  const expiresAt =
    passwordMode === 'static' || rotationDays === 0
      ? new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000).toISOString()
      : new Date(Date.now() + rotationDays * 24 * 60 * 60 * 1000).toISOString();
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO laps_vault (
      device_id, account_name, encrypted_password, iv, expires_at, last_rotated,
      previous_account_name, previous_encrypted_password, previous_iv, sid500_builtin_disabled,
      rotation_pending_online, pending_rotation_reason, pending_account_name
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(device_id) DO UPDATE SET
      previous_account_name = laps_vault.account_name,
      previous_encrypted_password = laps_vault.encrypted_password,
      previous_iv = laps_vault.iv,
      account_name = excluded.account_name,
      encrypted_password = excluded.encrypted_password,
      iv = excluded.iv,
      expires_at = excluded.expires_at,
      last_rotated = excluded.last_rotated,
      sid500_builtin_disabled = excluded.sid500_builtin_disabled,
      rotation_pending_online = excluded.rotation_pending_online,
      pending_rotation_reason = excluded.pending_rotation_reason,
      pending_account_name = excluded.pending_account_name
  `).run(
    deviceId,
    accountName,
    encryptedPayload,
    ivMarker,
    expiresAt,
    now,
    previousAccount,
    previousEncrypted,
    previousIv,
    sid500Disabled,
    pendingOnlineFlag,
    pendingOnlineReason,
    pendingOnlineFlag ? accountName : null
  );

  const renameNote =
    previousAccount && previousAccount !== accountName
      ? ` | Renamed from '${previousAccount}' -> '${accountName}' (Old Account Cleanup: ${cleanupAction.toUpperCase()})`
      : '';

  db.prepare(`
    INSERT INTO audit_logs (id, username, device_id, action, details)
    VALUES (?, ?, ?, 'LAPS Password Rotated', ?)
  `).run(
    `aud-laps-${crypto.randomUUID()}`,
    actor,
    deviceId,
    `Provisioned/Rotated account '${accountName}' on ${device.hostname} (Mode: ${passwordMode}, Auto-Create: ${autoCreateAccount ? 'Enabled' : 'Disabled'}, SID-500 Disabled: ${sid500Disabled ? 'Yes' : 'No'}, PendingOnline: ${pendingOnlineFlag ? 'Yes' : 'No'})${renameNote}`
  );

  return {
    deviceId,
    accountName,
    previousAccountName: previousAccount,
    password: shouldReveal ? newPass : MASK,
    previousPassword: shouldReveal
      ? decryptVaultSecret(previousEncrypted) || null
      : previousEncrypted
      ? MASK
      : null,
    passwordMode,
    autoCreateAccount,
    sid500BuiltinDisabled: Boolean(sid500Disabled),
    cleanupOldAccountAction: cleanupAction,
    expiresAt,
    lastRotated: now,
    autoRotateScheduled: false,
    rotationPendingOnline: Boolean(pendingOnlineFlag),
    pendingRotationReason: pendingOnlineReason,
    pendingAccountName: pendingOnlineFlag ? accountName : null,
    rotationStatus: pendingOnlineFlag ? 'deferred_until_online' : 'rotated_live'
  };
}

export interface BreakGlassRecoveryEntry {
  deviceId: string;
  hostname: string;
  tenantName: string;
  siteName: string;
  lifecycleState: string;
  serialNumber: string;
  osVersion: string;
  lapsAccountName: string;
  currentLapsPassword: string;
  previousLapsAccountName: string | null;
  previousLapsPassword: string | null;
  bitlockerRecoveryKey: string;
  bitlockerStatus: string;
  sid500BuiltinDisabled: boolean;
  lastRotated: string;
  offboardedAt: string | null;
}

export function exportLapsBreakGlassSheet(
  tenantId?: string,
  includeArchived = true,
  actorUsername = 'admin'
): {
  generatedAt: string;
  totalEndpoints: number;
  archivedIncludedCount: number;
  entries: BreakGlassRecoveryEntry[];
} {
  let sql = `
    SELECT d.*, t.name as tenant_name, s.name as site_name
    FROM devices d
    LEFT JOIN tenants t ON d.tenant_id = t.id
    LEFT JOIN sites s ON d.site_id = s.id
    WHERE 1=1
  `;
  const params: any[] = [];
  if (tenantId && tenantId !== 'all') {
    sql += ' AND d.tenant_id = ?';
    params.push(tenantId);
  }
  if (!includeArchived) {
    sql += " AND COALESCE(d.lifecycle_state, 'active') = 'active'";
  }
  sql += ' ORDER BY d.lifecycle_state ASC, t.name ASC, d.hostname ASC';

  const devices = db.prepare(sql).all(...params) as any[];
  const entries: BreakGlassRecoveryEntry[] = devices.map((d) => {
    const cred = getLapsCredential(d.id, true, {
      actorUsername,
      skipAccessExpiryMutation: true
    });
    const decryptedBitlocker = decryptVaultSecret(d.bitlocker_key);
    return {
      deviceId: d.id,
      hostname: d.hostname,
      tenantName: d.tenant_name || 'Unassigned',
      siteName: d.site_name || 'Default Site',
      lifecycleState: d.lifecycle_state || 'active',
      serialNumber: d.serial_number || 'N/A',
      osVersion: d.os_version,
      lapsAccountName: cred?.accountName || 'LocalAdmin',
      currentLapsPassword: cred?.password || 'N/A',
      previousLapsAccountName: cred?.previousAccountName || null,
      previousLapsPassword: cred?.previousPassword || null,
      bitlockerRecoveryKey: decryptedBitlocker || 'Not Escrowed',
      bitlockerStatus: d.bitlocker_status || 'Unknown',
      sid500BuiltinDisabled: Boolean(cred?.sid500BuiltinDisabled ?? true),
      lastRotated: cred?.lastRotated || d.last_seen,
      offboardedAt: d.offboarded_at || null
    };
  });

  db.prepare(`
    INSERT INTO audit_logs (id, username, action, details)
    VALUES (?, ?, 'Emergency Break-Glass Vault Export', ?)
  `).run(
    `aud-bg-${crypto.randomUUID()}`,
    actorUsername,
    `Exported emergency offline Break-Glass LAPS + BitLocker recovery sheet for ${entries.length} endpoint(s) (Archived included: ${includeArchived ? 'Yes' : 'No'}).`
  );

  return {
    generatedAt: new Date().toISOString(),
    totalEndpoints: entries.length,
    archivedIncludedCount: entries.filter((e) => e.lifecycleState === 'archived').length,
    entries
  };
}
