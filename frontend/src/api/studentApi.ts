import { isAxiosError } from 'axios';
import { apiClient } from './client';
import { instructorApi } from './instructorApi';
import type { ActivityStatus, Course } from '../types';
import { getDemoStudentEmail } from '../utils/demoAuth';

export type StudentDataSource = 'backend' | 'mock';
export type StudentAccessReason = 'NOT_STARTED' | 'ENDED' | 'UNAUTHORIZED';

export interface StudentActivitySummary {
  id: string;
  courseId: string;
  activityNumber: number;
  text: string;
  status?: ActivityStatus;
  score?: number;
  completed?: boolean;
}

export interface StudentCourse extends Course {
  activities: StudentActivitySummary[];
  source: StudentDataSource;
}

export interface StudentChatMessage {
  id: string;
  sender: 'student' | 'tutor';
  content: string;
  miniLesson?: string;
  isCelebration?: boolean;
  timestamp: string;
}

export interface StudentActivityDetail {
  id: string;
  courseId: string;
  activityNumber: number;
  title?: string;
  text: string;
  status: ActivityStatus;
  score: number;
  totalObjectives?: number;
  completed: boolean;
  nextQuestion?: string | null;
  chatHistory: StudentChatMessage[];
  source: StudentDataSource;
}

export interface StudentChatResponse {
  tutorMessage: string;
  score: number;
  scoreDelta: number;
  completed: boolean;
  status: ActivityStatus;
  nextQuestion?: string | null;
  miniLesson?: string;
  isMock: boolean;
}

export class StudentActivityAccessError extends Error {
  reason: StudentAccessReason;

  constructor(reason: StudentAccessReason, message: string) {
    super(message);
    this.name = 'StudentActivityAccessError';
    this.reason = reason;
  }
}

interface MockProgress {
  score: number;
  completed: boolean;
  awardedActiveRetrieval: boolean;
  awardedFeedback: boolean;
  chatHistory: StudentChatMessage[];
}

const mockProgressByKey: Record<string, MockProgress> = {};
const MOCK_TOTAL_OBJECTIVES = 2;
const MOCK_ACTIVITY_LOG_PREFIX = 'mockActivityLog:';

export const getMockProgressKey = (studentEmail: string, activityId: string) =>
  `studentProgress:${studentEmail}:${activityId}`;

const createMessageId = () => `${Date.now()}-${Math.random().toString(36).slice(2)}`;

const buildTutorMessage = (
  content: string,
  options: Pick<StudentChatMessage, 'miniLesson' | 'isCelebration'> = {},
): StudentChatMessage => ({
  id: createMessageId(),
  sender: 'tutor',
  content,
  timestamp: new Date().toISOString(),
  ...options,
});

const buildStudentMessage = (content: string): StudentChatMessage => ({
  id: createMessageId(),
  sender: 'student',
  content,
  timestamp: new Date().toISOString(),
});

const firstMockQuestion =
  'Question: How does active retrieval help a student learn from this activity?';

const feedbackMockQuestion =
  'Question: How can feedback help a student correct mistakes after trying an answer?';

const getAccessMessage = (reason: StudentAccessReason) => {
  if (reason === 'NOT_STARTED') return 'This activity has not started yet.';
  if (reason === 'ENDED') return 'This activity has ended.';
  return 'You are not authorized to access this activity.';
};

const mapAccessReason = (detail: unknown, statusCode?: number): StudentAccessReason => {
  const text = typeof detail === 'object'
    ? JSON.stringify(detail).toLowerCase()
    : String(detail ?? '').toLowerCase();
  if (text.includes('ended')) return 'ENDED';
  if (text.includes('not_started') || text.includes('not started') || text.includes('draft') || text.includes('only active')) {
    return 'NOT_STARTED';
  }
  if (statusCode === 404) return 'UNAUTHORIZED';
  return 'UNAUTHORIZED';
};

const shouldUseMockFallback = (error: unknown) => {
  if (!isAxiosError(error)) return true;
  if (!error.response) return true;

  const statusCode = error.response.status;
  const hasDemoToken = localStorage.getItem('demo_token') === 'mock-jwt-token';
  return statusCode === 404 || statusCode === 501 || (statusCode === 401 && hasDemoToken);
};

const throwAccessError = (error: unknown): never => {
  if (isAxiosError(error)) {
    const responseData =
      typeof error.response?.data === 'object' && error.response.data !== null
        ? (error.response.data as Record<string, unknown>)
        : undefined;
    const reason = mapAccessReason(
      responseData?.detail ?? responseData?.code ?? responseData?.status ?? error.response?.data,
      error.response?.status,
    );
    throw new StudentActivityAccessError(reason, getAccessMessage(reason));
  }

  throw new StudentActivityAccessError('UNAUTHORIZED', getAccessMessage('UNAUTHORIZED'));
};

const throwBackendChatError = (error: unknown): never => {
  if (isAxiosError(error)) {
    const statusCode = error.response?.status;
    if (statusCode === 401 || statusCode === 403 || statusCode === 404) {
      return throwAccessError(error);
    }
  }

  throw new Error('Unable to send your answer. Please try again.');
};

const throwBackendActivityError = (error: unknown): never => {
  if (isAxiosError(error)) {
    const statusCode = error.response?.status;
    if (statusCode === 401 || statusCode === 403 || statusCode === 404) {
      return throwAccessError(error);
    }
  }

  throw new Error('Unable to refresh this activity. Please try again.');
};

const normalizeStatus = (value: unknown): ActivityStatus | undefined => {
  const status = String(value ?? '').toUpperCase();
  if (status === 'NOT_STARTED' || status === 'ACTIVE' || status === 'ENDED') {
    return status;
  }
  return undefined;
};

const normalizeCourse = (raw: Record<string, unknown>): Course => ({
  id: String(raw.id ?? raw.course_id ?? ''),
  title: String(raw.title ?? raw.course_name ?? raw.name ?? raw.course_code ?? 'Untitled Course'),
  description: String(raw.description ?? raw.term ?? ''),
});

const normalizeActivitySummary = (
  raw: Record<string, unknown>,
  courseId: string,
): StudentActivitySummary => ({
  id: String(raw.id ?? raw.activity_id ?? ''),
  courseId: String(raw.courseId ?? raw.course_id ?? courseId),
  activityNumber: Number(raw.activityNumber ?? raw.activity_no ?? raw.activity_number ?? 1),
  text: String(raw.text ?? raw.activity_text ?? raw.description ?? raw.prompt ?? ''),
  status: normalizeStatus(raw.status),
  score: typeof raw.score === 'number' ? raw.score : undefined,
  completed: typeof raw.completed === 'boolean' ? raw.completed : undefined,
});

const normalizeMessage = (raw: unknown, index: number): StudentChatMessage => {
  const messageRaw =
    typeof raw === 'object' && raw !== null
      ? (raw as Record<string, unknown>)
      : { content: raw };
  const senderValue = String(messageRaw.sender ?? messageRaw.role ?? '').toLowerCase();
  const sender = senderValue === 'student' || senderValue === 'user' ? 'student' : 'tutor';

  return {
    id: String(messageRaw.id ?? `history-${index}`),
    sender,
    content: String(messageRaw.content ?? messageRaw.message ?? messageRaw.text ?? ''),
    miniLesson: messageRaw.miniLesson
      ? String(messageRaw.miniLesson)
      : messageRaw.mini_lesson
        ? String(messageRaw.mini_lesson)
        : undefined,
    isCelebration: Boolean(messageRaw.completed ?? messageRaw.isCelebration ?? messageRaw.is_celebration),
    timestamp: String(messageRaw.timestamp ?? new Date().toISOString()),
  };
};

const normalizeStoredMessages = (messages: unknown): StudentChatMessage[] => {
  if (!Array.isArray(messages)) return [];
  return messages.map((message, index) => normalizeMessage(message, index));
};

const normalizeMockProgress = (raw: unknown): MockProgress | null => {
  if (typeof raw !== 'object' || raw === null) return null;
  const candidate = raw as Partial<MockProgress>;

  return {
    score: typeof candidate.score === 'number' ? candidate.score : 0,
    completed: Boolean(candidate.completed),
    awardedActiveRetrieval: Boolean(candidate.awardedActiveRetrieval),
    awardedFeedback: Boolean(candidate.awardedFeedback),
    chatHistory: normalizeStoredMessages(candidate.chatHistory),
  };
};

const readStoredMockProgress = (key: string): MockProgress | null => {
  const memoryProgress = mockProgressByKey[key];
  if (memoryProgress) return memoryProgress;

  const storedProgress = localStorage.getItem(key);
  if (!storedProgress) return null;

  try {
    const normalizedProgress = normalizeMockProgress(JSON.parse(storedProgress));
    if (!normalizedProgress) return null;
    mockProgressByKey[key] = normalizedProgress;
    return normalizedProgress;
  } catch {
    localStorage.removeItem(key);
    return null;
  }
};

const persistMockProgress = (key: string, progress: MockProgress) => {
  mockProgressByKey[key] = progress;
  localStorage.setItem(key, JSON.stringify(progress));
};

const persistMockActivityLog = (
  activityId: string,
  studentEmail: string,
  score: number,
  eventType: string,
  objectiveMetadata: Record<string, unknown>,
) => {
  const timestamp = new Date().toISOString();
  const id = `${activityId}:${studentEmail}:${eventType}:${timestamp}`;

  localStorage.setItem(
    `${MOCK_ACTIVITY_LOG_PREFIX}${id}`,
    JSON.stringify({
      id,
      activityId,
      studentName: studentEmail,
      score,
      objectiveMetadata,
      timestamp,
      eventType,
    }),
  );
};

const stripObjectiveFields = (raw: Record<string, unknown>): Record<string, unknown> => {
  const studentSafeRaw = { ...raw };
  delete studentSafeRaw.objectives;
  delete studentSafeRaw.learningObjectives;
  delete studentSafeRaw.learning_objectives;
  return studentSafeRaw;
};

const normalizeActivityDetail = (
  raw: Record<string, unknown>,
  activityId: string,
): StudentActivityDetail => {
  const studentSafeRaw = stripObjectiveFields(raw);
  const courseId = String(studentSafeRaw.courseId ?? studentSafeRaw.course_id ?? '');
  const chatRaw = Array.isArray(studentSafeRaw.chatHistory)
    ? studentSafeRaw.chatHistory
    : Array.isArray(studentSafeRaw.chat_history)
      ? studentSafeRaw.chat_history
      : [];
  const chatHistory = chatRaw.map((message, index) => normalizeMessage(message, index));
  const nextQuestion = studentSafeRaw.nextQuestion ?? studentSafeRaw.next_question ?? null;

  if (nextQuestion && chatHistory.length === 0) {
    chatHistory.push(buildTutorMessage(String(nextQuestion)));
  }

  return {
    id: String(studentSafeRaw.id ?? studentSafeRaw.activity_id ?? activityId),
    courseId,
    activityNumber: Number(studentSafeRaw.activityNumber ?? studentSafeRaw.activity_no ?? studentSafeRaw.activity_number ?? 1),
    title: studentSafeRaw.title ? String(studentSafeRaw.title) : undefined,
    text: String(studentSafeRaw.text ?? studentSafeRaw.activity_text ?? studentSafeRaw.description ?? studentSafeRaw.prompt ?? ''),
    status: normalizeStatus(studentSafeRaw.status) ?? 'ACTIVE',
    score: Number(studentSafeRaw.score ?? studentSafeRaw.current_score ?? 0),
    totalObjectives: studentSafeRaw.totalObjectives
      ? Number(studentSafeRaw.totalObjectives)
      : studentSafeRaw.total_objectives
        ? Number(studentSafeRaw.total_objectives)
        : undefined,
    completed: Boolean(studentSafeRaw.completed ?? studentSafeRaw.is_completed),
    nextQuestion: nextQuestion ? String(nextQuestion) : null,
    chatHistory,
    source: 'backend',
  };
};

const requireOpenActivity = (activity: StudentActivityDetail): StudentActivityDetail => {
  if (activity.status === 'NOT_STARTED') {
    throw new StudentActivityAccessError('NOT_STARTED', getAccessMessage('NOT_STARTED'));
  }

  if (activity.status === 'ENDED') {
    throw new StudentActivityAccessError('ENDED', getAccessMessage('ENDED'));
  }

  return activity;
};

const findMockActivity = async (activityId: string) => {
  const courses = await instructorApi.getCourses();

  for (const course of courses) {
    const activities = await instructorApi.getCourseActivities(course.id);
    const activity = activities.find((item) => item.id === activityId);
    if (activity) return { course, activity };
  }

  throw new StudentActivityAccessError('UNAUTHORIZED', getAccessMessage('UNAUTHORIZED'));
};

const getMockProgress = (
  studentEmail: string,
  activityId: string,
  activityText: string,
): MockProgress => {
  const key = getMockProgressKey(studentEmail, activityId);
  const existing = readStoredMockProgress(key);
  if (existing) return existing;

  const progress: MockProgress = {
    score: 0,
    completed: false,
    awardedActiveRetrieval: false,
    awardedFeedback: false,
    chatHistory: [
      buildTutorMessage(`Activity text: ${activityText}\n\n${firstMockQuestion}`),
    ],
  };
  persistMockProgress(key, progress);
  return progress;
};

const getNextMockQuestion = (progress: MockProgress) => {
  if (!progress.awardedActiveRetrieval) return firstMockQuestion;
  if (!progress.awardedFeedback) return feedbackMockQuestion;
  return null;
};

const getMockStudentCourses = async (): Promise<StudentCourse[]> => {
  const studentEmail = getDemoStudentEmail();
  const courses = await instructorApi.getCourses();
  const coursesWithActivities = await Promise.all(
    courses.map(async (course) => {
      const activities = await instructorApi.getCourseActivities(course.id);
      return {
        ...course,
        activities: activities
          .sort((left, right) => left.activityNumber - right.activityNumber)
          .map((activity) => {
            const progress = readStoredMockProgress(getMockProgressKey(studentEmail, activity.id));
            return {
              id: activity.id,
              courseId: activity.courseId,
              activityNumber: activity.activityNumber,
              text: activity.text,
              status: activity.status,
              score: progress?.score,
              completed: progress?.completed,
            };
          }),
        source: 'mock' as const,
      };
    }),
  );

  return coursesWithActivities;
};

const getMockStudentActivity = async (activityId: string): Promise<StudentActivityDetail> => {
  const { course, activity } = await findMockActivity(activityId);

  if (activity.status === 'NOT_STARTED') {
    throw new StudentActivityAccessError('NOT_STARTED', getAccessMessage('NOT_STARTED'));
  }

  if (activity.status === 'ENDED') {
    throw new StudentActivityAccessError('ENDED', getAccessMessage('ENDED'));
  }

  const studentEmail = getDemoStudentEmail();
  const progress = getMockProgress(studentEmail, activity.id, activity.text);

  return {
    id: activity.id,
    courseId: course.id,
    activityNumber: activity.activityNumber,
    title: `Activity ${activity.activityNumber}`,
    text: activity.text,
    status: activity.status,
    score: progress.score,
    totalObjectives: MOCK_TOTAL_OBJECTIVES,
    completed: progress.completed,
    nextQuestion: getNextMockQuestion(progress),
    chatHistory: progress.chatHistory,
    source: 'mock',
  };
};

const runMockChat = async (activityId: string, answer: string): Promise<StudentChatResponse> => {
  const { activity } = await findMockActivity(activityId);

  if (activity.status === 'NOT_STARTED') {
    throw new StudentActivityAccessError('NOT_STARTED', getAccessMessage('NOT_STARTED'));
  }

  if (activity.status === 'ENDED') {
    throw new StudentActivityAccessError('ENDED', getAccessMessage('ENDED'));
  }

  const studentEmail = getDemoStudentEmail();
  const progressKey = getMockProgressKey(studentEmail, activity.id);
  const progress = getMockProgress(studentEmail, activity.id, activity.text);
  progress.chatHistory.push(buildStudentMessage(answer));

  const normalizedAnswer = answer.toLowerCase();
  const mentionsActiveRetrieval =
    normalizedAnswer.includes('active retrieval') ||
    normalizedAnswer.includes('retrieval practice') ||
    normalizedAnswer.includes('recall') ||
    normalizedAnswer.includes('remember without');
  const mentionsFeedback =
    normalizedAnswer.includes('feedback') ||
    normalizedAnswer.includes('correcting mistakes') ||
    normalizedAnswer.includes('correct mistakes') ||
    normalizedAnswer.includes('fix mistakes') ||
    normalizedAnswer.includes('errors');

  let scoreDelta = 0;
  let miniLesson: string | undefined;
  let tutorMessage = 'No new point yet. Add a more specific idea and try again.';

  if (mentionsActiveRetrieval && !progress.awardedActiveRetrieval) {
    progress.awardedActiveRetrieval = true;
    progress.score += 1;
    scoreDelta = 1;
    miniLesson = 'Active retrieval means pulling an idea from memory before seeing the answer. That effort makes the learning stickier than rereading alone.';
    tutorMessage = `Nice, you earned +1 for active retrieval. Your score is now ${progress.score}.`;
    persistMockActivityLog(activityId, studentEmail, progress.score, 'OBJECTIVE_SCORE', {
      objective: 'Active retrieval',
      answer,
      grading_type: 'mock',
    });
  } else if (mentionsFeedback && !progress.awardedFeedback) {
    progress.awardedFeedback = true;
    progress.score += 1;
    scoreDelta = 1;
    miniLesson = 'Feedback works best when it points to the mistake and gives the learner a chance to revise, so the correction becomes part of the next attempt.';
    tutorMessage = `Strong connection, you earned +1 for feedback and correcting mistakes. Your score is now ${progress.score}.`;
    persistMockActivityLog(activityId, studentEmail, progress.score, 'OBJECTIVE_SCORE', {
      objective: 'Feedback and correcting mistakes',
      answer,
      grading_type: 'mock',
    });
  } else if (
    (mentionsActiveRetrieval && progress.awardedActiveRetrieval) ||
    (mentionsFeedback && progress.awardedFeedback)
  ) {
    tutorMessage = `That idea was already counted, so your score stays ${progress.score}.`;
  }

  progress.completed = progress.score >= MOCK_TOTAL_OBJECTIVES;
  const nextQuestion = getNextMockQuestion(progress);

  if (progress.completed) {
    tutorMessage = `Excellent work, you completed the activity. Your final score is ${progress.score}.`;
    persistMockActivityLog(activityId, studentEmail, progress.score, 'SUBMISSION', {
      completed: true,
      grading_type: 'mock',
    });
  } else if (nextQuestion) {
    tutorMessage = `${tutorMessage}\n\n${nextQuestion}`;
  }

  const tutorChatMessage = buildTutorMessage(tutorMessage, {
    miniLesson,
    isCelebration: progress.completed,
  });
  progress.chatHistory.push(tutorChatMessage);
  persistMockProgress(progressKey, progress);

  return {
    tutorMessage,
    score: progress.score,
    scoreDelta,
    completed: progress.completed,
    status: activity.status,
    nextQuestion,
    miniLesson,
    isMock: true,
  };
};

const normalizeChatResponse = (raw: Record<string, unknown>): StudentChatResponse => {
  const completed = Boolean(raw.completed ?? raw.is_completed);
  const score = Number(raw.score ?? raw.updated_score ?? raw.current_score ?? 0);
  const message = String(raw.tutorMessage ?? raw.tutor_message ?? raw.message ?? raw.response ?? '');
  const nextQuestion = raw.nextQuestion ?? raw.next_question ?? null;
  const status = normalizeStatus(raw.status) ?? 'ACTIVE';

  return {
    tutorMessage: nextQuestion && !completed ? `${message}\n\nQuestion: ${String(nextQuestion)}` : message,
    score,
    scoreDelta: Number(raw.scoreDelta ?? raw.score_delta ?? 0),
    completed,
    status,
    nextQuestion: nextQuestion ? String(nextQuestion) : null,
    miniLesson: raw.miniLesson ? String(raw.miniLesson) : raw.mini_lesson ? String(raw.mini_lesson) : undefined,
    isMock: false,
  };
};

export const studentApi = {
  getCourses: async (): Promise<StudentCourse[]> => {
    try {
      const response = await apiClient.get('/student/courses');
      const rawCourses = Array.isArray(response.data) ? response.data : response.data?.courses ?? [];
      return rawCourses.map((raw: Record<string, unknown>) => {
        const course = normalizeCourse(raw);
        const rawActivities = Array.isArray(raw.activities)
          ? raw.activities
          : Array.isArray(raw.available_activities)
            ? raw.available_activities
            : [];

        return {
          ...course,
          activities: rawActivities.map((activity) =>
            normalizeActivitySummary(activity as Record<string, unknown>, course.id),
          ),
          source: 'backend' as const,
        };
      });
    } catch (error) {
      if (shouldUseMockFallback(error)) {
        return getMockStudentCourses();
      }
      return throwAccessError(error);
    }
  },

  getActivity: async (
    activityId: string,
    source?: StudentDataSource,
  ): Promise<StudentActivityDetail> => {
    if (source === 'mock') {
      return getMockStudentActivity(activityId);
    }

    try {
      const response = await apiClient.get(`/student/activities/${activityId}`);
      return requireOpenActivity(normalizeActivityDetail(response.data, activityId));
    } catch (error) {
      if (source === 'backend') {
        return throwBackendActivityError(error);
      }

      if (shouldUseMockFallback(error)) {
        return getMockStudentActivity(activityId);
      }
      return throwAccessError(error);
    }
  },

  sendChatMessage: async (
    activityId: string,
    answer: string,
    source?: StudentDataSource,
  ): Promise<StudentChatResponse> => {
    if (source === 'mock') {
      return runMockChat(activityId, answer);
    }

    try {
      const response = await apiClient.post(`/student/activities/${activityId}/chat`, { answer });
      return normalizeChatResponse(response.data);
    } catch (error) {
      if (source === 'backend') {
        return throwBackendChatError(error);
      }

      if (shouldUseMockFallback(error)) {
        return runMockChat(activityId, answer);
      }
      return throwAccessError(error);
    }
  },
};
