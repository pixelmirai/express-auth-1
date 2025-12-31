const usersService = require('./users.service');

const getMe = async (req, res, next) => {
  try {
    const user = await usersService.getCurrentUser(req.user.id);
    res.json({ status: 'success', data: { user } });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getMe,
};
