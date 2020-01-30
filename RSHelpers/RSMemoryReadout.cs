using RockSnifferLib.Logging;
using System;
using Newtonsoft.Json;

namespace RockSnifferLib.RSHelpers
{
    [Serializable]
    public class RSMemoryReadout
    {
        public float songTimer = 0;
        public string songID = "";
        public string persistentID = "";

        public RSMode mode = RSMode.UNKNOWN;
        public string gameState = "";

        [JsonIgnore]
        public BasicNoteData LASData = new BasicNoteData();
        [JsonIgnore]
        public ScoreAttackData SAData = new ScoreAttackData();

        public BasicNoteData noteData
        {
            get
            {
                return mode == RSMode.SCOREATTACK ? SAData : LASData;
            }
        }


        /// <summary>
        /// Prints out this readouts details (if Logger.logMemoryOutput is enabled)
        /// </summary>
        public void Print()
        {
            if (Logger.logMemoryReadout)
            {
                Logger.Log("State: {0} Mode: {1}", gameState, mode);
                if (mode == RSMode.LEARNASONG)
                {
                    Logger.Log("PID: {0} SID: {1}", persistentID, songID);
                    LASData.Print(songTimer);
                }
                else if (mode == RSMode.SCOREATTACK)
                {
                    Logger.Log("PID: {0} SID: {1}", persistentID, songID);
                    SAData.Print(songTimer);
                }
            }
        }

        /// <summary>
        /// Copy the fields from this readout to another
        /// </summary>
        /// <param name="copy">target readout</param>
        internal void CopyTo(ref RSMemoryReadout copy)
        {
            copy.songTimer = songTimer;
            copy.songID = songID;
            copy.persistentID = persistentID;

            copy.mode = mode;
            copy.gameState = gameState;

            LASData.CopyTo(ref copy);
            SAData.CopyTo(ref copy);
        }

        /// <summary>
        /// Returns a copy of this memory readout
        /// </summary>
        /// <returns></returns>
        public RSMemoryReadout Clone()
        {
            RSMemoryReadout copy = new RSMemoryReadout();

            CopyTo(ref copy);

            return copy;
        }
    }
    public class BasicNoteData
    {
        public int TotalNotesHit = 0;
        public int CurrentHitStreak = 0;
        public int HighestHitStreak = 0;
        public int TotalNotesMissed = 0;
        public int CurrentMissStreak = 0;
        public int TotalNotes
        {
            get
            {
                return TotalNotesMissed + TotalNotesHit;
            }
        }
        public virtual void Print(float songTimer)
        {
            Logger.Log("t: {0}, hits: {1}, misses: {2} streak: {3}, hstreak: {4}, mstreak:{5}", songTimer, TotalNotesHit, TotalNotesMissed,
                CurrentHitStreak, HighestHitStreak, CurrentMissStreak);
        }

        public virtual void CopyTo(ref RSMemoryReadout copy)
        {
            if (copy.mode == RSMode.LEARNASONG)
            {
                copy.LASData.TotalNotesHit = TotalNotesHit;
                copy.LASData.CurrentHitStreak = CurrentHitStreak;
                copy.LASData.HighestHitStreak = HighestHitStreak;
                copy.LASData.TotalNotesMissed = TotalNotesMissed;
                copy.LASData.CurrentMissStreak = CurrentMissStreak;
            }
        }
        public virtual void Clear()
        {
            TotalNotesHit = CurrentHitStreak = HighestHitStreak = TotalNotesMissed = CurrentHitStreak = 0;
        }
    }
    public class ScoreAttackData : BasicNoteData
    {
        /* Score Attack Fields */
        public int CurrentPerfectHitStreak = 0;
        public int TotalPerfectHits = 0;
        public int CurrentLateHitStreak = 0;
        public int TotalLateHits = 0;
        public int PerfectPhrases = 0;
        public int GoodPhrases = 0;
        public int PassedPhrases = 0;
        public int FailedPhrases = 0;

        public override void Clear()
        {
            base.Clear();
            CurrentPerfectHitStreak = TotalPerfectHits = CurrentLateHitStreak = TotalLateHits = CurrentHitStreak = 0;
            PerfectPhrases = GoodPhrases = PassedPhrases = FailedPhrases = 0;
        }
        public override void Print(float songTimer)
        {
            Logger.Log("t: {0}, hits: {1}, misses: {2} streak: {3}, hstreak: {4}, mstreak:{5}", songTimer, TotalNotesHit, TotalNotesMissed,
                     CurrentHitStreak, HighestHitStreak, CurrentMissStreak);
            Logger.Log("cphstreak: {0} totalPerfect: {1} clstreak: {2} totalLate: {3}", CurrentPerfectHitStreak, TotalPerfectHits, CurrentLateHitStreak, TotalLateHits);
            Logger.Log("Phrases passed: {0} failed: {1} good: {2} perfect: {3}", PassedPhrases, FailedPhrases, GoodPhrases, PerfectPhrases);
        }
        public override void CopyTo(ref RSMemoryReadout copy)
        {
            if (copy.mode == RSMode.SCOREATTACK)
            {
                copy.SAData.TotalNotesHit = TotalNotesHit;
                copy.SAData.CurrentHitStreak = CurrentHitStreak;
                copy.SAData.HighestHitStreak = HighestHitStreak;
                copy.SAData.TotalNotesMissed = TotalNotesMissed;
                copy.SAData.CurrentMissStreak = CurrentMissStreak;

                copy.SAData.CurrentPerfectHitStreak = CurrentPerfectHitStreak;
                copy.SAData.TotalPerfectHits = TotalPerfectHits;
                copy.SAData.CurrentLateHitStreak = CurrentLateHitStreak;
                copy.SAData.TotalLateHits = TotalLateHits;

                copy.SAData.PassedPhrases = PassedPhrases;
                copy.SAData.FailedPhrases = FailedPhrases;
                copy.SAData.GoodPhrases = GoodPhrases;
                copy.SAData.PerfectPhrases = PerfectPhrases;
            }
        }
    }
}
