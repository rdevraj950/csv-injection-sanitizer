export function sanitizeByRemovingCharacters(input: string): string {
  const sanitizedInput = input
    .replace(/^\s*[-|+|@|=|\t|\r]+/, "")
    .replace(/([;,'"\`]\s*)([-|+|@|=|\t|\r]+)/g, "$1");

  return sanitizedInput;
}
