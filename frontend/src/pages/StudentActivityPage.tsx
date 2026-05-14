import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  Lock,
  PartyPopper,
  Send,
  Trophy,
} from 'lucide-react';
import {
  StudentActivityAccessError,
  studentApi,
  type StudentActivityDetail,
  type StudentChatMessage,
} from '../api/studentApi';
import { ChatMessage } from '../components/ChatMessage';
import { StatusBadge } from '../components/StatusBadge';

const createStudentMessage = (content: string): StudentChatMessage => ({
  id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
  sender: 'student',
  content,
  timestamp: new Date().toISOString(),
});

const createTutorMessage = (
  content: string,
  miniLesson?: string,
  isCelebration = false,
): StudentChatMessage => ({
  id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
  sender: 'tutor',
  content,
  miniLesson,
  isCelebration,
  timestamp: new Date().toISOString(),
});

export const StudentActivityPage: React.FC = () => {
  const { activityId } = useParams<{ activityId: string }>();
  const navigate = useNavigate();
  const chatEndRef = useRef<HTMLDivElement | null>(null);
  const sendInFlightRef = useRef(false);

  const [activity, setActivity] = useState<StudentActivityDetail | null>(null);
  const [messages, setMessages] = useState<StudentChatMessage[]>([]);
  const [answer, setAnswer] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let isActive = true;

    const loadActivity = async () => {
      if (!activityId) return;

      try {
        setIsLoading(true);
        setError('');
        const data = await studentApi.getActivity(activityId);
        if (!isActive) return;
        setActivity(data);
        setMessages(data.chatHistory);
      } catch (err) {
        if (!isActive) return;
        if (err instanceof StudentActivityAccessError) {
          setError(err.message);
        } else {
          setError(err instanceof Error ? err.message : 'Unable to open this activity.');
        }
      } finally {
        if (isActive) setIsLoading(false);
      }
    };

    loadActivity();

    return () => {
      isActive = false;
    };
  }, [activityId]);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      chatEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [messages.length]);

  const completedObjectives = activity?.score ?? 0;
  const progressText = useMemo(() => {
    const objectiveWord = completedObjectives === 1 ? 'objective' : 'objectives';
    if (activity?.totalObjectives) {
      const totalObjectiveWord = activity.totalObjectives === 1 ? 'objective' : 'objectives';
      return `${completedObjectives} of ${activity.totalObjectives} ${totalObjectiveWord} completed`;
    }
    return `${completedObjectives} ${objectiveWord} completed`;
  }, [activity?.totalObjectives, completedObjectives]);

  const disabledReason = useMemo(() => {
    if (!activity) return '';
    if (activity.status === 'NOT_STARTED') return 'This activity has not started yet.';
    if (activity.status === 'ENDED') return 'This activity has ended.';
    if (activity.completed) return 'Activity completed.';
    return '';
  }, [activity]);

  const statusBanner = useMemo(() => {
    if (!activity) return '';
    if (activity.status === 'NOT_STARTED') return 'This activity has not started yet.';
    if (activity.status === 'ENDED') return 'This activity has ended. Your chat input is disabled.';
    return '';
  }, [activity]);

  const activitySource = activity?.source;
  const isActivityCompleted = Boolean(activity?.completed);

  useEffect(() => {
    if (!activityId || !activitySource || disabledReason || isActivityCompleted) return;

    const intervalId = window.setInterval(async () => {
      try {
        await studentApi.getActivity(activityId, activitySource);
      } catch (err) {
        if (!(err instanceof StudentActivityAccessError)) return;
        if (err.reason !== 'ENDED' && err.reason !== 'NOT_STARTED') return;

        const activityStatus = err.reason === 'ENDED' ? 'ENDED' : 'NOT_STARTED';
        setError(err.message);
        setActivity((currentActivity) =>
          currentActivity ? { ...currentActivity, status: activityStatus } : currentActivity,
        );
      }
    }, 3000);

    return () => window.clearInterval(intervalId);
  }, [activityId, activitySource, isActivityCompleted, disabledReason]);

  const submitAnswer = async () => {
    if (!activityId || !activity || disabledReason || sendInFlightRef.current) return;

    const trimmedAnswer = answer.trim();
    if (!trimmedAnswer) return;

    sendInFlightRef.current = true;
    const studentMessage = createStudentMessage(trimmedAnswer);
    setMessages((currentMessages) => [...currentMessages, studentMessage]);
    setAnswer('');
    setIsSending(true);
    setError('');

    try {
      const response = await studentApi.sendChatMessage(activityId, trimmedAnswer, activity.source);
      const tutorMessage = createTutorMessage(
        response.tutorMessage,
        response.miniLesson,
        response.completed,
      );

      setMessages((currentMessages) => [...currentMessages, tutorMessage]);
      setActivity((currentActivity) =>
        currentActivity
          ? {
              ...currentActivity,
              score: response.score,
              completed: response.completed,
              status: response.status,
              nextQuestion: response.nextQuestion,
              source: currentActivity.source,
            }
          : currentActivity,
      );
    } catch (err) {
      setMessages((currentMessages) =>
        currentMessages.filter((message) => message.id !== studentMessage.id),
      );
      if (err instanceof StudentActivityAccessError) {
        setError(err.message);
        if (err.reason === 'ENDED' || err.reason === 'NOT_STARTED') {
          const activityStatus = err.reason === 'ENDED' ? 'ENDED' : 'NOT_STARTED';
          setActivity((currentActivity) =>
            currentActivity ? { ...currentActivity, status: activityStatus } : currentActivity,
          );
        }
      } else {
        setError(err instanceof Error ? err.message : 'Unable to send your answer.');
      }
    } finally {
      sendInFlightRef.current = false;
      setIsSending(false);
    }
  };

  const handleSend = (event: React.FormEvent) => {
    event.preventDefault();
    void submitAnswer();
  };

  const handleAnswerKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key !== 'Enter' || event.shiftKey) return;
    event.preventDefault();
    void submitAnswer();
  };

  if (isLoading) {
    return <div className="py-10 text-center text-gray-600">Loading activity...</div>;
  }

  if (error && !activity) {
    return (
      <div className="mx-auto max-w-2xl">
        <button
          type="button"
          onClick={() => navigate('/student/dashboard')}
          className="mb-4 inline-flex items-center rounded-md px-2 py-2 text-sm font-semibold text-gray-600 transition-colors hover:bg-gray-100 hover:text-gray-900"
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to dashboard
        </button>
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-6 text-amber-900">
          <div className="flex items-center gap-2 font-semibold">
            <Lock className="h-5 w-5" />
            Activity unavailable
          </div>
          <p className="mt-2 text-sm">{error}</p>
        </div>
      </div>
    );
  }

  if (!activity) {
    return null;
  }

  return (
    <div className="space-y-6">
      <button
        type="button"
        onClick={() => navigate('/student/dashboard')}
        className="inline-flex items-center rounded-md px-2 py-2 text-sm font-semibold text-gray-600 transition-colors hover:bg-gray-100 hover:text-gray-900"
      >
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back to dashboard
      </button>

      <section className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide text-indigo-600">
              Activity {activity.activityNumber}
            </p>
            <h1 className="mt-1 text-2xl font-bold text-gray-900">{activity.title ?? 'Student Activity'}</h1>
          </div>
          <StatusBadge status={activity.status} />
        </div>
        <p className="text-base leading-7 text-gray-800">{activity.text}</p>
      </section>

      {activity.source === 'mock' && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          Mock tutoring mode is active. The scoring below is separated from backend scoring.
        </div>
      )}

      {statusBanner && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm font-medium text-red-800">
          {statusBanner}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-50 text-indigo-700">
              <Trophy className="h-5 w-5" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Current score</p>
              <p className="text-2xl font-bold text-gray-900">
                {activity.score}
                {activity.totalObjectives ? <span className="text-base text-gray-400"> / {activity.totalObjectives}</span> : null}
              </p>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm md:col-span-2">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-50 text-emerald-700">
              <CheckCircle2 className="h-5 w-5" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Progress</p>
              <p className="text-lg font-semibold text-gray-900">{progressText}</p>
            </div>
          </div>
        </div>
      </div>

      {activity.completed && (
        <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-5 text-emerald-900">
          <div className="flex items-center gap-2 font-semibold">
            <PartyPopper className="h-5 w-5" />
            Celebration
          </div>
          <p className="mt-2 text-sm">You completed this activity. The chat is now closed.</p>
        </div>
      )}

      {error && activity && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">
          <div className="flex items-center gap-2 font-semibold">
            <AlertCircle className="h-4 w-4" />
            Chat unavailable
          </div>
          <p className="mt-1">{error}</p>
        </div>
      )}

      <section className="rounded-lg border border-gray-200 bg-gray-100 p-4 shadow-sm sm:p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <h2 className="text-lg font-bold text-gray-900">Tutor Chat</h2>
          {disabledReason && (
            <span className="rounded-full bg-gray-200 px-3 py-1 text-xs font-semibold text-gray-700">
              {disabledReason}
            </span>
          )}
        </div>

        <div className="flex max-h-[52vh] min-h-[320px] flex-col gap-4 overflow-y-auto rounded-lg bg-gray-50 p-3 sm:p-4">
          {messages.length === 0 ? (
            <div className="flex flex-1 items-center justify-center text-sm text-gray-500">
              Waiting for the tutor question...
            </div>
          ) : (
            messages.map((message) => <ChatMessage key={message.id} message={message} />)
          )}
          <div ref={chatEndRef} />
        </div>

        <form onSubmit={handleSend} className="mt-4 flex flex-col gap-3 sm:flex-row">
          <textarea
            value={answer}
            onChange={(event) => setAnswer(event.target.value)}
            onKeyDown={handleAnswerKeyDown}
            disabled={Boolean(disabledReason) || isSending}
            rows={2}
            className="min-h-12 flex-1 resize-none rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm transition-colors focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:cursor-not-allowed disabled:bg-gray-100 disabled:text-gray-500"
            placeholder={disabledReason || 'Type your answer'}
          />
          <button
            type="submit"
            disabled={Boolean(disabledReason) || isSending || !answer.trim()}
            className="inline-flex items-center justify-center rounded-md border border-transparent bg-indigo-600 px-5 py-3 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:bg-gray-300"
          >
            <Send className="mr-2 h-4 w-4" />
            {isSending ? 'Sending...' : 'Send'}
          </button>
        </form>
      </section>
    </div>
  );
};
