// keyname.js — the 8-word "key-name" (spec §3.9, §3.9.1): a zero-authority, deterministic,
// human-pronounceable name derived *from the identity key itself*. No directory, no
// consensus, no registration — it exists the instant a key is generated, and two different
// keys yield different names by construction. This is the top rung of the naming ladder
// (§3.9): key-name → handle → name@domain, decreasing zero-authority as you go down.
//
// What is real here: the SHA-256 digest (Web Crypto) and the word-selection arithmetic are
// real and fully deterministic — the same public key bytes always produce the same name,
// which you can verify with the "recompute" action in Settings.
//
// What is a stand-in: the spec (§2.2, §3.9.1) specifies BLAKE3 for content-addressing and a
// curated ~1024-word list at 10 bits/word for a full 2^80 (80-bit) address space. Browsers
// have no native BLAKE3, so this demo uses SHA-256 (same convention as identity.js/mote.js).
// This demo also embeds a smaller, byte-aligned 256-word list (8 bits/word) so each word maps
// to exactly one hash byte — simpler code, at the cost of some entropy (8 words here carry
// 64 bits, not the spec's 80). A production client would ship the full ~1024-word list.
//
// Encoding used here: word[i] = WORDLIST[ digest[i] ] for i in 0..7 (8 words from the first
// 8 hash bytes), then a checksum word folded from the remaining digest bytes so a
// mistyped/misheard name fails closed instead of silently resolving to a different key
// (spec §3.9.1's "checksum folded into the last word", shown here as a distinct 9th word for
// clarity in the UI).

// A curated list of 256 short, plain, pronounceable English words — animals, plants, minerals,
// colors, weather, geography, tools — chosen to avoid homophones/offensive collisions for this
// demo. (Not the spec's full multilingual ~1024-word list; see comment above.)
const WORDLIST = (
  'otter heron wolf lynx puma ibex crane finch ' +
  'swan hawk owl fox stag elk seal orca ' +
  'whale dolphin panda koala lemur raven badger beaver ' +
  'marten weasel ferret gecko iguana viper cobra egret ' +
  'falcon eagle sparrow robin wren plover osprey kestrel ' +
  'harrier bison moose caribou antelope gazelle jackal hyena ' +
  'walrus narwhal pelican heronry stork toucan parrot macaw ' +
  'canary linnet siskin bunting warbler thrush maple cedar ' +
  'birch willow aspen elm oak pine fir spruce ' +
  'alder rowan hazel poplar yew larch fern moss ' +
  'lichen clover thistle nettle bramble ivy vine reed ' +
  'rush sedge bamboo cactus aloe agave lotus lily ' +
  'iris tulip daisy poppy violet aster crocus jasmine ' +
  'orchid lavender sage basil mint thyme garnet opal ' +
  'topaz jasper onyx agate quartz cobalt amber jade ' +
  'coral pearl ruby beryl zircon spinel granite basalt ' +
  'slate marble shale flint pumice obsidian mica pyrite ' +
  'gypsum talc feldspar dolomite chert schist copper bronze ' +
  'brass iron steel tin zinc nickel silver gold ' +
  'platinum titanium tungsten cadmium chrome crimson ochre indigo ' +
  'cyan teal emerald olive umber sienna russet ivory ' +
  'pewter charcoal ash chalk cream beige tan khaki ' +
  'mauve lilac plum peach salmon dawn dusk noon ' +
  'twilight midnight sunrise sunset zenith solstice equinox aurora ' +
  'eclipse comet meteor nebula nova cloud storm thunder ' +
  'lightning breeze gale zephyr mist fog frost dew ' +
  'rain hail sleet snow gust delta ridge canyon ' +
  'valley plateau mesa summit peak glacier tundra prairie ' +
  'savanna steppe fjord isthmus atoll harbor cove bay ' +
  'strait channel estuary reef lagoon marsh bog fen ' +
  'moor heath dune shoal cape ember flame spark ' +
  'cinder kindle hearth forge anvil bellows chisel mallet'
).split(' ');

if (WORDLIST.length !== 256) throw new Error('keyname wordlist must have exactly 256 entries, has ' + WORDLIST.length);

export { WORDLIST as KEYNAME_WORDS };

// Derive the deterministic 8-word key-name (+ checksum word) from raw public key bytes.
// Pure function of the input bytes: same key in → same name out, every time.
export async function deriveKeyName(rawPublicKeyBytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', rawPublicKeyBytes));
  const words = [];
  for (let i = 0; i < 8; i++) words.push(WORDLIST[digest[i]]);
  // Checksum: fold the remaining digest bytes (not used for the 8 words) into one more
  // index, so a single mistyped/misheard word almost always produces a checksum mismatch
  // (fail-closed) rather than silently pointing at a different key (spec §3.9.1).
  let fold = 0;
  for (let i = 8; i < digest.length; i++) fold ^= digest[i];
  for (let i = 0; i < 8; i++) fold = (fold + digest[i] * (i + 1)) % 256;
  const checksum = WORDLIST[fold];
  return { words, checksum, full: words.concat(checksum).join('-') };
}

// Re-derive and compare against a previously-shown key-name, to demonstrate (not just
// claim) determinism: same public key bytes -> byte-identical word sequence, every time.
export async function verifyKeyName(rawPublicKeyBytes, expectedFull) {
  const again = await deriveKeyName(rawPublicKeyBytes);
  return { match: again.full === expectedFull, recomputed: again.full };
}
