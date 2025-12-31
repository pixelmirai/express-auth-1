const prisma = require('../../database/prisma/client');
const { createNotFoundError } = require('../../utils/errors');

const sanitizeUser = (user) => {
  if (!user) return null;
  const { passwordHash, ...rest } = user;
  return rest;
};

const handlePrismaNotFound = (error) => {
  if (error?.code === 'P2025') {
    throw createNotFoundError('User not found');
  }
  throw error;
};

const listUsers = async () => {
  const users = await prisma.user.findMany({ orderBy: { createdAt: 'desc' } });
  return users.map(sanitizeUser);
};

const getUserById = async (id) => {
  const user = await prisma.user.findUnique({ where: { id } });
  if (!user) {
    throw createNotFoundError('User not found');
  }
  return sanitizeUser(user);
};

const banUser = async (id) => {
  try {
    const user = await prisma.user.update({
      where: { id },
      data: { status: 'banned' },
    });
    return sanitizeUser(user);
  } catch (error) {
    handlePrismaNotFound(error);
  }
};

const unbanUser = async (id) => {
  try {
    const user = await prisma.user.update({
      where: { id },
      data: { status: 'active' },
    });
    return sanitizeUser(user);
  } catch (error) {
    handlePrismaNotFound(error);
  }
};

const deleteUser = async (id) => {
  const user = await prisma.user.findUnique({ where: { id } });
  if (!user) {
    throw createNotFoundError('User not found');
  }

  await prisma.$transaction([
    prisma.refreshToken.deleteMany({ where: { userId: id } }),
    prisma.emailVerificationToken.deleteMany({ where: { userId: id } }),
    prisma.passwordResetToken.deleteMany({ where: { userId: id } }),
    prisma.loginLog.deleteMany({ where: { userId: id } }),
    prisma.user.delete({ where: { id } }),
  ]);
};

module.exports = {
  listUsers,
  getUserById,
  banUser,
  unbanUser,
  deleteUser,
};
