namespace BoletoHibridoBradesco.Helpers
{
    /// <summary>
    /// See https://en.wikipedia.org/wiki/Unix_time />
    /// </summary>
    public abstract class UnixEpochHelper
    {
        #region Private Constructors

        private UnixEpochHelper()
        {
        }

        #endregion Private Constructors

        #region Public Properties

        /// <summary>
        /// See https://en.wikipedia.org/wiki/Unix_time />
        /// </summary>
        public static DateTime Value { get; } = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        #endregion Public Properties

        #region Public Methods

        /// <summary>
        /// Recupera o total de segundos entre as datas e o epoch
        /// </summary>
        /// <param name="time">Data</param>
        /// <returns></returns>
        public static long GetSecondsSince(DateTimeOffset time) => (long)Math.Round((time - Value).TotalSeconds);

        /// <summary>
        /// Recupera o total de segundos entre as datas e o epoch
        /// </summary>
        /// <param name="time">Data</param>
        /// <returns></returns>
        public static long GetSecondsSince(DateTime time) => (long)GetSecondsSince(new DateTimeOffset(time));

        #endregion Public Methods
    }
}