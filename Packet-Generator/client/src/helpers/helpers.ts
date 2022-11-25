/** Style constants */
const STYLES = {
  maxWidth: '90%',
};

/** Color palette */
const PALETTE = {
  darkBlue: '#22577e',
  blue: '#5584ac',
  lightCyan: '#95d1cc',
  beige: '#f6f2d4',
  white: '#ffffff',
};

/** Check if the provided string can be parsed as an IPv4 address with a RegEx */
const isIPv4 = (str: string): boolean => {
  const regEx =
    /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

  return regEx.test(str);
};

/** General helpers */
const helpers = {
  STYLES,
  PALETTE,
  isIPv4,
};

export default helpers;
