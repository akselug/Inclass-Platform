import { apiClient } from './client';
import type { Role, User } from '../types';

const normalizeRole = (role: string | null): Role | null => {
  if (!role) return null;
  const normalized = role.toUpperCase();
  if (normalized === 'INSTRUCTOR' || normalized === 'STUDENT' || normalized === 'ADMIN') {
    return normalized as Role;
  }
  return null;
};

const mapMeToUser = (raw: Record<string, any>): User => {
  const role = normalizeRole(String(raw.role ?? ''));
  if (!role) throw new Error('Invalid role from server');
  return {
    id: String(raw.user_id ?? raw.id ?? ''),
    email: String(raw.email ?? ''),
    name: String(raw.name ?? raw.full_name ?? raw.email ?? 'User'),
    role,
  };
};

export const authApi = {
  login: async (role: Role, email: string, password: string): Promise<{ token: string }> => {
    const endpoint =
      role === 'INSTRUCTOR' ? '/instructor/login' : '/student/login';
    const res = await apiClient.post(endpoint, { email, password });
    const data = res.data as Record<string, any>;
    const token = String(data.access_token ?? '');
    if (!token) throw new Error('No access token returned');
    return { token };
  },

  studentRegister: async (fullName: string, email: string, password: string, confirmPassword: string): Promise<{ token: string }> => {
    const res = await apiClient.post('/student/register', { 
      full_name: fullName, 
      email, 
      password, 
      confirm_password: confirmPassword 
    });
    const data = res.data as Record<string, any>;
    const token = String(data.access_token ?? '');
    if (!token) throw new Error('No access token returned');
    return { token };
  },

  getGoogleConfig: async (): Promise<{ clientId: string; schoolEmailDomain: string }> => {
    const envClientId = String(import.meta.env.VITE_GOOGLE_CLIENT_ID ?? '');
    if (envClientId) {
      return {
        clientId: envClientId,
        schoolEmailDomain: String(import.meta.env.VITE_SCHOOL_EMAIL_DOMAIN ?? ''),
      };
    }

    const res = await apiClient.get('/auth/google/config');
    const data = res.data as Record<string, any>;
    return {
      clientId: String(data.client_id ?? ''),
      schoolEmailDomain: String(data.school_email_domain ?? ''),
    };
  },

  googleStudentLogin: async (idToken: string): Promise<{ token: string }> => {
    const res = await apiClient.post('/auth/google/student', { id_token: idToken });
    const data = res.data as Record<string, any>;
    const token = String(data.access_token ?? '');
    if (!token) throw new Error('No access token returned');
    return { token };
  },

  getMe: async (): Promise<User> => {
    const res = await apiClient.get('/auth/me');
    return mapMeToUser(res.data as Record<string, any>);
  },
};
