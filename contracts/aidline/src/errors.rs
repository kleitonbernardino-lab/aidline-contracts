use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    Unauthorized = 1,
    CampaignNotFound = 2,
    DeadlineInPast = 3,
    InvalidMilestones = 4,
    InvalidAmount = 5,
    CampaignNotActive = 6,
    CampaignExpired = 7,
    GoalExceeded = 8,
    NotVerifier = 9,
    MilestoneNotFunded = 10,
    NoMilestonesLeft = 11,
    RefundNotAvailable = 12,
    NothingToRefund = 13,

    // Issue #27: sponsor matching pools
    SponsorPoolExists = 14,
    SponsorPoolNotFound = 15,
    InvalidMatchingConfig = 16,
    PoolNotReturnable = 17,

    // Issue #29: verifier bonds
    BondRequired = 18,
    BondNotFound = 19,
    BondNotWithdrawable = 20,
    WithdrawDelayNotMet = 21,
    SlashExceedsBond = 22,

    // Issue #30: pledges
    InvalidPledge = 23,

    // Issue #23: emergency fast track
    NotEmergencyCampaign = 24,
    AdvanceAlreadyTaken = 25,
    AdvanceExceedsEscrow = 26,

    // Issue #9: multisig verification
    InvalidThreshold = 27,
    DuplicateApproval = 28,
    DuplicateVerifier = 29,

    // Issue #10: per-campaign token allowlist
    TokenNotAllowed = 30,

    // Emergency pause switch
    Paused = 31,

    // Metadata update
    DonationsAlreadyStarted = 32,

    // Deadline extension
    DeadlineAlreadyExtended = 33,
    InvalidDeadlineExtension = 34,

    // URI length limit
    UriTooLong = 35,

    // Conflict of interest
    ConflictOfInterest = 36,

    // Optional minimum donation
    DonationBelowMinimum = 37,

    // Two-step admin transfer
    NoPendingAdmin = 38,

    // Pledges
    PledgeAlreadyCancelled = 39,

    // Verifier reassignment
    MaxVerifierReassignmentsExceeded = 40,

    // Issue #143: Bounded proof URI
    InvalidProofUri = 41,
}
