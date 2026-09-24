export function isCanonicalCIDR(value: string) {
  const [address, length, extra] = value.trim().split("/")
  if (!address || !length || extra !== undefined || !/^\d+$/.test(length)) return false
  const bits = Number(length)
  let numeric = 0n
  let width = 32

  if (address.includes(":")) {
    width = 128
    if (bits > width || (address.match(/::/g)?.length ?? 0) > 1) return false
    const [left, right = ""] = address.split("::")
    const leftParts = left ? left.split(":") : []
    const rightParts = right ? right.split(":") : []
    if ([...leftParts, ...rightParts].some((part) => !/^[0-9a-f]{1,4}$/i.test(part))) return false
    const missing = 8 - leftParts.length - rightParts.length
    if ((address.includes("::") && missing < 1) || (!address.includes("::") && missing !== 0)) return false
    const groups = [...leftParts, ...Array.from({ length: missing }, () => "0"), ...rightParts]
    numeric = groups.reduce((sum, group) => (sum << 16n) + BigInt(`0x${group}`), 0n)
  } else {
    const octets = address.split(".")
    if (bits > width || octets.length !== 4 || octets.some((part) => !/^\d+$/.test(part) || Number(part) > 255)) return false
    numeric = octets.reduce((sum, octet) => (sum << 8n) + BigInt(octet), 0n)
  }

  const hostBits = BigInt(width - bits)
  const hostMask = hostBits === 0n ? 0n : (1n << hostBits) - 1n
  return (numeric & hostMask) === 0n
}
