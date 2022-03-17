package log_test

import (
	"testing"

	logger "github.com/TykTechnologies/tyk/log"
	"github.com/sirupsen/logrus"
)

func TestLogQuoting(t *testing.T) {
	log := logger.Get()
	log.Warnf("%s", "\rhello\n")
	log.Warnf("%v", "\rhello\n")
	log.Warnf("%q", "\rhello\n")

	log.WithFields(logrus.Fields{
		"text": "\rhello\n",
	}).Info("hey")

	rawLog := logger.GetRaw()
	rawLog.Info("\rhello\n")

	logger.LoadTranslations(map[string]interface{}{
		"foo": "bar",
	})
	log.WithField("code", "foo").Info("foo")
}
