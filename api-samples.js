const axios = require('axios');

async function checkHealth(baseURL = 'http://localhost:3000') {
  const response = await axios.get(`${baseURL}/health`);
  return response.data;
}

async function register(baseURL = 'http://localhost:3000') {
  const response = await axios.post(`${baseURL}/auth/register`, {
    email: 'new.user@example.com',
    password: 'P@ssw0rd123!',
    name: 'New User',
  });
  return response.data;
}

async function login(baseURL = 'http://localhost:3000') {
  const response = await axios.post(`${baseURL}/auth/login`, {
    email: 'new.user@example.com',
    password: 'P@ssw0rd123!',
  }, {
    withCredentials: true,
  });
  return response.data;
}

async function loginWithGoogle(baseURL = 'http://localhost:3000') {
  const response = await axios.post(`${baseURL}/auth/login/google`, {
    idToken: 'sample-google-id-token',
  }, {
    withCredentials: true,
  });
  return response.data;
}

async function refreshTokens(baseURL = 'http://localhost:3000') {
  const refreshToken = 'sample-refresh-token';
  const response = await axios.post(`${baseURL}/auth/refresh`, {
    refreshToken,
  }, {
    headers: { Authorization: `Bearer ${refreshToken}` },
    withCredentials: true,
  });
  return response.data;
}

async function logout(baseURL = 'http://localhost:3000') {
  const refreshToken = 'sample-refresh-token';
  const response = await axios.post(`${baseURL}/auth/logout`, {
    refreshToken,
  }, {
    headers: { Authorization: `Bearer ${refreshToken}` },
    withCredentials: true,
  });
  return response.data;
}

async function logoutAllSessions(baseURL = 'http://localhost:3000') {
  const accessToken = 'sample-access-token';
  const response = await axios.post(`${baseURL}/auth/logout-all`, {}, {
    headers: { Authorization: `Bearer ${accessToken}` },
    withCredentials: true,
  });
  return response.data;
}

async function verifyEmail(baseURL = 'http://localhost:3000') {
  const response = await axios.post(`${baseURL}/auth/verify-email`, {
    token: 'sample-email-verification-token',
  });
  return response.data;
}

async function requestPasswordReset(baseURL = 'http://localhost:3000') {
  const response = await axios.post(`${baseURL}/auth/request-password-reset`, {
    email: 'existing.user@example.com',
  });
  return response.data;
}

async function resetPassword(baseURL = 'http://localhost:3000') {
  const response = await axios.post(`${baseURL}/auth/reset-password`, {
    token: 'sample-reset-token',
    password: 'N3wP@ssword!',
  });
  return response.data;
}

async function getMe(baseURL = 'http://localhost:3000') {
  const accessToken = 'sample-access-token';
  const response = await axios.get(`${baseURL}/users/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return response.data;
}

async function listUsers(baseURL = 'http://localhost:3000') {
  const adminAccessToken = 'admin-access-token';
  const response = await axios.get(`${baseURL}/admin/users`, {
    headers: { Authorization: `Bearer ${adminAccessToken}` },
  });
  return response.data;
}

async function getUserById(baseURL = 'http://localhost:3000', userId = 'user-id-123') {
  const adminAccessToken = 'admin-access-token';
  const response = await axios.get(`${baseURL}/admin/users/${userId}`, {
    headers: { Authorization: `Bearer ${adminAccessToken}` },
  });
  return response.data;
}

async function banUser(baseURL = 'http://localhost:3000', userId = 'user-id-123') {
  const adminAccessToken = 'admin-access-token';
  const response = await axios.patch(`${baseURL}/admin/users/${userId}/ban`, {}, {
    headers: { Authorization: `Bearer ${adminAccessToken}` },
  });
  return response.data;
}

async function unbanUser(baseURL = 'http://localhost:3000', userId = 'user-id-123') {
  const adminAccessToken = 'admin-access-token';
  const response = await axios.patch(`${baseURL}/admin/users/${userId}/unban`, {}, {
    headers: { Authorization: `Bearer ${adminAccessToken}` },
  });
  return response.data;
}

async function deleteUser(baseURL = 'http://localhost:3000', userId = 'user-id-123') {
  const adminAccessToken = 'admin-access-token';
  const response = await axios.delete(`${baseURL}/admin/users/${userId}/delete`, {
    headers: { Authorization: `Bearer ${adminAccessToken}` },
  });
  return response.status;
}

module.exports = {
  checkHealth,
  register,
  login,
  loginWithGoogle,
  refreshTokens,
  logout,
  logoutAllSessions,
  verifyEmail,
  requestPasswordReset,
  resetPassword,
  getMe,
  listUsers,
  getUserById,
  banUser,
  unbanUser,
  deleteUser,
};
