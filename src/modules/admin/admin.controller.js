const adminService = require('./admin.service');

const listUsers = async (req, res, next) => {
  try {
    const users = await adminService.listUsers();
    res.json({ status: 'success', data: { users } });
  } catch (error) {
    next(error);
  }
};

const getUserById = async (req, res, next) => {
  try {
    const user = await adminService.getUserById(req.params.id);
    res.json({ status: 'success', data: { user } });
  } catch (error) {
    next(error);
  }
};

const banUser = async (req, res, next) => {
  try {
    const user = await adminService.banUser(req.params.id);
    res.json({ status: 'success', data: { user } });
  } catch (error) {
    next(error);
  }
};

const unbanUser = async (req, res, next) => {
  try {
    const user = await adminService.unbanUser(req.params.id);
    res.json({ status: 'success', data: { user } });
  } catch (error) {
    next(error);
  }
};

const deleteUser = async (req, res, next) => {
  try {
    await adminService.deleteUser(req.params.id);
    res.status(204).send();
  } catch (error) {
    next(error);
  }
};

module.exports = {
  listUsers,
  getUserById,
  banUser,
  unbanUser,
  deleteUser,
};
