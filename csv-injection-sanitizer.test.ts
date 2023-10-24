import { sanitizeByRemovingCharacters } from "./csv-injection-sanitizer";

const eachTestRunner = (_: unknown, input: string, expected: string) =>
  testRunner(input, expected);
const testRunner = (input: string, expected: string) => {
  const actual = sanitizeByRemovingCharacters(input);

  expect(actual).toEqual(expected);
};

describe("csv-injection-sanitizer", () => {
  it("attack vector 1", () => {
    const input = "hello world, @@nastystuffhere, hello =world";
    const expected = "hello world, nastystuffhere, hello =world";

    testRunner(input, expected);
  });

  it("attack vector 2", () => {
    const input = " +--@- hello @world";
    const expected = " hello @world";

    testRunner(input, expected);
  });

  it("attack vector 3", () => {
    const input = `hello world,
@+-\t\r=and @universe`;
    const expected = `hello world,
and @universe`;

    testRunner(input, expected);
  });

  it("attack vector 4", () => {
    const input = ",@  @hello world";
    const expected = ",hello world";

    testRunner(input, expected);
  });

  it.each([
    [1, "i want to talk to @tomato"],
    [2, ";:hello world"],
    [
      3,
      `hello world
    @and universe`,
    ],
    [
      4,
      `Hello world, this is my newest long post
    I hope everything is going well for @all or you remember that \`1 + 1 - 1 = 1; \tand we @enjoy it #all :dont we?`,
    ],
  ])("should not sanitize, test case %s", (_: unknown, input: string) => {
    const actual = sanitizeByRemovingCharacters(input);

    expect(actual).toEqual(input);
  });

  it.each([
    [1, "-hello world", "hello world"],
    [2, "+hello world", "hello world"],
    [3, "@hello world", "hello world"],
    [4, "=hello world", "hello world"],
    [5, "\thello world", "hello world"],
    [6, "\rhello world", "hello world"],
  ])(
    "should remove untrusted characters from start of string, test case %s",
    eachTestRunner
  );

  it.each([
    [1, "hello,-world", "hello,world"],
    [2, "hello,+world", "hello,world"],
    [3, "hello,@world", "hello,world"],
    [4, "hello,=world", "hello,world"],
    [5, "hello,\tworld", "hello,world"],
    [6, "hello,\rworld", "hello,world"],
  ])(
    "should remove untrusted characters from middle, test case %s",
    eachTestRunner
  );

  it.each([
    [1, "hello,==world", "hello,world"],
    [2, "hello;==world", "hello;world"],
    [3, 'hello"==world', 'hello"world'],
    [4, "hello'==world", "hello'world"],
    [5, "hello`==world", "hello`world"],
  ])(
    "should remove untrusted characters after all types of quotes and line breaks, test case %s",
    eachTestRunner
  );
});
