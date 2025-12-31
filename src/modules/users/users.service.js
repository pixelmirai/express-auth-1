const prisma = require('../../database/prisma/client');

const sanitizeUser = (user) => {
  if (!user) return null;
  const { passwordHash, ...rest } = user;
  return rest;
};

const getCurrentUser = async (userId) => {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  return sanitizeUser(user);
};

module.exports = {
  getCurrentUser,
};
