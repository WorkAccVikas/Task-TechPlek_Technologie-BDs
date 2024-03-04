export const DB_NAME = "TechPlek_Technologies";

export const USER_ROLE_TYPE = {
  Admin: "Admin",
  User: "User",
};

export const ROLES_ENUM = Object.values(USER_ROLE_TYPE);

export const MAX_PASSWORD_LENGTH = 5;

export const SECURE_COOKIE_OPTION = {
  httpOnly: true,
  // secure: true,
};

export const REFRESH_TOKEN_EXPIRY_TIME = 24 * 60 * 60 * 1000; // 1 DAY

export const ACCESS_TOKEN_EXPIRY_TIME = 1 * 60 * 60 * 1000; // 1 HOUR
// export const ACCESS_TOKEN_EXPIRY_TIME = 30 * 1000; // 30 seconds
