using RockSnifferLib.Logging;
using System;

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

        public BasicNoteData LASData = new BasicNoteData();
        public ScoreAttackData SAData = new ScoreAttackData();



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
        public int totalNotesHit = 0;
        public int currentHitStreak = 0;
        public int highestHitStreak = 0;
        public int totalNotesMissed = 0;
        public int currentMissStreak = 0;
        public int TotalNotes
        {
            get
            {
                return totalNotesMissed + totalNotesHit;
            }
        }
        public virtual void Print(float songTimer)
        {
            Logger.Log("t: {0}, hits: {1}, misses: {2} streak: {3}, hstreak: {4}, mstreak:{5}", songTimer, totalNotesHit, totalNotesMissed,
                currentHitStreak, highestHitStreak, currentMissStreak);
        }

        public virtual void CopyTo(ref RSMemoryReadout copy)
        {
            if (copy.mode == RSMode.LEARNASONG)
            {
                copy.LASData.totalNotesHit = totalNotesHit;
                copy.LASData.currentHitStreak = currentHitStreak;
                copy.LASData.highestHitStreak = highestHitStreak;
                copy.LASData.totalNotesMissed = totalNotesMissed;
                copy.LASData.currentMissStreak = currentMissStreak;
            }
        }

    }
    public class ScoreAttackData : BasicNoteData
    {
        /* Score Attack Fields */
        public int currentPerfectHitStreak = 0;
        public int totalPerfectHits = 0;
        public int currentLateHitStreak = 0;
        public int totalLateHits = 0;
        public int perfectPhrases = 0;
        public int goodPhrases = 0;
        public int passedPhrases = 0;
        public int failedPhrases = 0;

        public override void Print(float songTimer)
        {
            Logger.Log("t: {0}, hits: {1}, misses: {2} streak: {3}, hstreak: {4}, mstreak:{5}", songTimer, totalNotesHit, totalNotesMissed,
                     currentHitStreak, highestHitStreak, currentMissStreak);
            Logger.Log("cphstreak: {0} totalPerfect: {1} clstreak: {2} totalLate: {3}", currentPerfectHitStreak, totalPerfectHits, currentLateHitStreak, totalLateHits);
            Logger.Log("Phrases passed: {0} failed: {1} good: {2} perfect: {3}", passedPhrases, failedPhrases, goodPhrases, perfectPhrases);
        }
        public override void CopyTo(ref RSMemoryReadout copy)
        {
            if (copy.mode == RSMode.SCOREATTACK)
            {
                copy.SAData.totalNotesHit = totalNotesHit;
                copy.SAData.currentHitStreak = currentHitStreak;
                copy.SAData.highestHitStreak = highestHitStreak;
                copy.SAData.totalNotesMissed = totalNotesMissed;
                copy.SAData.currentMissStreak = currentMissStreak;

                copy.SAData.currentPerfectHitStreak = currentPerfectHitStreak;
                copy.SAData.totalPerfectHits = totalPerfectHits;
                copy.SAData.currentLateHitStreak = currentLateHitStreak;
                copy.SAData.totalLateHits = totalLateHits;

                copy.SAData.passedPhrases = passedPhrases;
                copy.SAData.failedPhrases = failedPhrases;
                copy.SAData.goodPhrases = goodPhrases;
                copy.SAData.perfectPhrases = perfectPhrases;
            }
        }
    }
}
