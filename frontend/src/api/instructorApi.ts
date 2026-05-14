
import { apiClient } from './client';
import type { Course, Activity, ActivityLog } from '../types';

// Mock data
let mockActivities: Activity[] = [
  {
    id: 'act-1',
    courseId: 'course-1',
    activityNumber: 1,
    text: 'Explain how active retrieval and targeted feedback help students correct mistakes during learning.',
    status: 'NOT_STARTED',
    learningObjectives: ['Explain active retrieval as recall from memory', 'Explain how feedback helps students correct mistakes'],
  },
  {
    id: 'act-2',
    courseId: 'course-1',
    activityNumber: 2,
    text: 'Design a system architecture for a real-time chat application.',
    status: 'ACTIVE',
    learningObjectives: ['System design principles', 'Real-time communication protocols'],
  },
];

const mockCourses: Course[] = [
  { id: 'course-1', title: 'Introduction to Computer Science', description: 'Basic concepts of programming.' },
  { id: 'course-2', title: 'Advanced Software Engineering', description: 'Design patterns and scalable architectures.' },
];

const mockLogs: ActivityLog[] = [
  {
    id: 'log-1',
    activityId: 'act-2',
    studentName: 'Alice Johnson',
    score: 85,
    objectiveMetadata: { 'System design principles': 'Good', 'Real-time communication protocols': 'Needs Improvement' },
    timestamp: new Date().toISOString(),
    eventType: 'SUBMISSION',
  },
  {
    id: 'log-2',
    activityId: 'act-2',
    studentName: 'Bob Williams',
    score: 92,
    objectiveMetadata: { 'System design principles': 'Excellent', 'Real-time communication protocols': 'Good' },
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    eventType: 'SUBMISSION',
  },
];

const MOCK_ACTIVITY_LOG_PREFIX = 'mockActivityLog:';
const MOCK_PROGRESS_PREFIX = 'studentProgress:';

const normalizeActivityStatus = (value: unknown): Activity['status'] => {
  const status = String(value ?? '').toUpperCase();
  if (status === 'DRAFT' || status === 'NOT_STARTED') return 'NOT_STARTED';
  if (status === 'ACTIVE') return 'ACTIVE';
  if (status === 'ENDED') return 'ENDED';
  return 'NOT_STARTED';
};

const normalizeObjectives = (value: unknown): string[] => {
  if (Array.isArray(value)) return value.map((item) => String(item));
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed)) return parsed.map((item) => String(item));
    } catch {
      return value.trim() ? [value] : [];
    }
  }
  return [];
};

const normalizeCourse = (raw: Record<string, unknown>): Course => ({
  id: String(raw.id ?? raw.course_id ?? ''),
  title: String(raw.title ?? raw.course_name ?? raw.name ?? raw.course_code ?? 'Untitled Course'),
  description: String(raw.description ?? raw.term ?? ''),
});

const normalizeActivity = (
  raw: Record<string, unknown>,
  courseId: string,
): Activity => ({
  id: String(raw.id ?? raw.activity_id ?? ''),
  courseId: String(raw.courseId ?? raw.course_id ?? courseId),
  activityNumber: Number(raw.activityNumber ?? raw.activity_no ?? raw.activity_number ?? 1),
  text: String(raw.text ?? raw.activity_text ?? raw.description ?? raw.prompt ?? ''),
  status: normalizeActivityStatus(raw.status ?? raw.activity_status),
  learningObjectives: normalizeObjectives(
    raw.learningObjectives ?? raw.learning_objectives ?? raw.objectives,
  ),
});

const getActivityLocation = async (activityId: string): Promise<Activity> => {
  const mockActivity = mockActivities.find((activity) => activity.id === activityId);
  if (mockActivity) return mockActivity;

  const courses = await instructorApi.getCourses();
  for (const course of courses) {
    const activities = await instructorApi.getCourseActivities(course.id);
    const activity = activities.find((item) => item.id === activityId);
    if (activity) return activity;
  }

  throw new Error('Activity not found');
};

const getStoredMockLogs = (activityId: string): ActivityLog[] => {
  const logs: ActivityLog[] = [];

  for (let index = 0; index < localStorage.length; index += 1) {
    const key = localStorage.key(index);
    if (!key?.startsWith(MOCK_ACTIVITY_LOG_PREFIX)) continue;

    const value = localStorage.getItem(key);
    if (!value) continue;

    try {
      const parsed = JSON.parse(value) as ActivityLog;
      if (parsed.activityId === activityId) logs.push(parsed);
    } catch {
      localStorage.removeItem(key);
    }
  }

  return logs;
};

const getSyntheticLogsFromMockProgress = (activityId: string): ActivityLog[] => {
  const logs: ActivityLog[] = [];

  for (let index = 0; index < localStorage.length; index += 1) {
    const key = localStorage.key(index);
    if (!key?.startsWith(MOCK_PROGRESS_PREFIX) || !key.endsWith(`:${activityId}`)) continue;

    const value = localStorage.getItem(key);
    if (!value) continue;

    try {
      const parsed = JSON.parse(value) as { score?: unknown; completed?: unknown };
      const [, studentEmail] = key.split(':');
      logs.push({
        id: `progress:${studentEmail}:${activityId}`,
        activityId,
        studentName: studentEmail || 'Unknown student',
        score: typeof parsed.score === 'number' ? parsed.score : null,
        objectiveMetadata: { completed: Boolean(parsed.completed), source: 'mock_progress' },
        timestamp: new Date().toISOString(),
        eventType: Boolean(parsed.completed) ? 'SUBMISSION' : 'PROGRESS',
      });
    } catch {
      localStorage.removeItem(key);
    }
  }

  return logs;
};

export const instructorApi = {
  getCourses: async (): Promise<Course[]> => {
    try {
      const response = await apiClient.get('/instructor/courses');
      const rawCourses = Array.isArray(response.data) ? response.data : response.data?.courses ?? [];
      return rawCourses.map((raw: Record<string, unknown>) => normalizeCourse(raw));
    } catch {
      return new Promise<Course[]>((resolve) => setTimeout(() => resolve(mockCourses), 300));
    }
  },

  getCourseActivities: async (courseId: string): Promise<Activity[]> => {
    try {
      const response = await apiClient.get('/instructor/activities', {
        params: { course_id: courseId },
      });
      const rawActivities = Array.isArray(response.data) ? response.data : response.data?.activities ?? [];
      return rawActivities.map((raw: Record<string, unknown>) => normalizeActivity(raw, courseId));
    } catch {
      return new Promise<Activity[]>((resolve) => 
        setTimeout(() => resolve(mockActivities.filter(a => a.courseId === courseId)), 300)
      );
    }
  },

  createActivity: async (courseId: string, data: Omit<Activity, 'id' | 'courseId' | 'status'>): Promise<Activity> => {
    try {
      const response = await apiClient.post('/instructor/activity/create', {
        course_id: courseId,
        activity_no: data.activityNumber,
        activity_text: data.text,
        objectives: data.learningObjectives,
      });
      return normalizeActivity(response.data as Record<string, unknown>, courseId);
    } catch {
      return new Promise<Activity>((resolve) => {
        setTimeout(() => {
          const newActivity: Activity = {
            ...data,
            id: `act-${Date.now()}`,
            courseId,
            status: 'NOT_STARTED',
          };
          mockActivities.push(newActivity);
          resolve(newActivity);
        }, 300);
      });
    }
  },

  updateActivity: async (activityId: string, data: Partial<Activity>): Promise<Activity> => {
    try {
      const activity = await getActivityLocation(activityId);
      await apiClient.patch(`/instructor/activity/${activity.courseId}/${activity.activityNumber}`, {
        activity_text: data.text,
        objectives: data.learningObjectives,
      });
      return { ...activity, ...data };
    } catch {
      return new Promise<Activity>((resolve, reject) => {
        setTimeout(() => {
          const index = mockActivities.findIndex(a => a.id === activityId);
          if (index > -1) {
            mockActivities[index] = { ...mockActivities[index], ...data };
            resolve(mockActivities[index]);
          } else {
            reject(new Error('Activity not found'));
          }
        }, 300);
      });
    }
  },

  startActivity: async (activityId: string): Promise<Activity> => {
    try {
      const activity = await getActivityLocation(activityId);
      await apiClient.post('/instructor/activity/start', null, {
        params: { course_id: activity.courseId, activity_no: activity.activityNumber },
      });
      return { ...activity, status: 'ACTIVE' };
    } catch {
      return instructorApi.updateActivity(activityId, { status: 'ACTIVE' });
    }
  },

  endActivity: async (activityId: string): Promise<Activity> => {
    try {
      const activity = await getActivityLocation(activityId);
      await apiClient.post('/instructor/activity/end', null, {
        params: { course_id: activity.courseId, activity_no: activity.activityNumber },
      });
      return { ...activity, status: 'ENDED' };
    } catch {
      return instructorApi.updateActivity(activityId, { status: 'ENDED' });
    }
  },

  resetActivity: async (activityId: string): Promise<Activity> => {
    try {
      const activity = await getActivityLocation(activityId);
      await apiClient.post('/instructor/activity/reset', null, {
        params: { course_id: activity.courseId, activity_no: activity.activityNumber },
      });
      return { ...activity, status: 'ENDED' };
    } catch {
      return instructorApi.updateActivity(activityId, { status: 'ENDED' });
    }
  },

  getActivityLogs: async (activityId: string): Promise<ActivityLog[]> => {
    try {
      const response = await apiClient.get(`/instructor/activities/${activityId}/logs`);
      const rawLogs = Array.isArray(response.data) ? response.data : response.data?.logs ?? [];
      return rawLogs.map((raw: Record<string, unknown>) => ({
        id: String(raw.id ?? ''),
        activityId: String(raw.activityId ?? raw.activity_id ?? activityId),
        studentName: String(raw.studentName ?? raw.student_name ?? raw.studentEmail ?? raw.student_email ?? 'Unknown student'),
        score: raw.score === null || raw.score === undefined ? null : Number(raw.score),
        objectiveMetadata: raw.objectiveMetadata ?? raw.objective_metadata ?? {},
        timestamp: String(raw.timestamp ?? raw.created_at ?? raw.updated_at ?? new Date().toISOString()),
        eventType: String(raw.eventType ?? raw.event_type ?? 'SUBMISSION'),
      }));
    } catch {
      const allMockLogs = [
        ...mockLogs,
        ...getStoredMockLogs(activityId),
        ...getSyntheticLogsFromMockProgress(activityId),
      ];
      return new Promise<ActivityLog[]>((resolve) => 
        setTimeout(() => resolve(allMockLogs.filter(l => l.activityId === activityId)), 300)
      );
    }
  },
};
