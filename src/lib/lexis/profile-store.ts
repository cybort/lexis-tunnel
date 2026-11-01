import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";
import { defaultProfile, normalizeProfile, type LexisProfile } from "./profile";

type ProfileState = {
  profile: LexisProfile;
  setProfile: (profile: LexisProfile) => void;
  patch: (partial: Partial<LexisProfile>) => void;
};

export const useProfile = create<ProfileState>()(
  persist(
    (set) => ({
      profile: defaultProfile(),
      setProfile: (profile) => set({ profile: normalizeProfile(profile) }),
      patch: (partial) => set((state) => ({ profile: normalizeProfile({ ...state.profile, ...partial }) })),
    }),
    {
      name: "lexis-profile-v1",
      storage: createJSONStorage(() => localStorage),
      skipHydration: true,
      version: 1,
      merge: (persisted, current) => {
        const saved = persisted as Partial<ProfileState> | undefined;
        return { ...current, profile: normalizeProfile(saved?.profile ?? current.profile) };
      },
    },
  ),
);
