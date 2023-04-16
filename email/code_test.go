package email

import "testing"

func TestNewCodeEmailBadEmailAddress(t *testing.T) {
	ce, status, err := NewCodeEmail("bad_email_address", "123456")
	if ce != (CodeEmail{}) {
		t.Error("failed to return empty CodeEmail struct on receiving bad email address")
	}

	if status != Invalid {
		t.Error("failed to return status of Invalid on receiving bad email address")
	}

	if err == nil {
		t.Error("failed to return error on receiving bad email address")
	}
}

func TestNewCodeEmailBadCode(t *testing.T) {
	ce, status, err := NewCodeEmail("good_email_address@email.com", "1234567")
	if ce != (CodeEmail{}) {
		t.Error("failed to return empty CodeEmail struct on receiving bad code")
	}

	if status != Invalid {
		t.Error("failed to return status of Invalid on receiving bad email code")
	}

	if err == nil {
		t.Error("failed to return error on receiving bad code")
	}
}

func TestValidCodeEmail(t *testing.T) {
	ce, status, err := NewCodeEmail("good_email_address@gmail.com", "123456")
	if ce != (CodeEmail{"good_email_address@gmail.com", "123456"}) {
		t.Error("failed to return the correct CodeEmail struct on receiving valid email and code")
	}

	if status != Success {
		t.Error("failed to return status of Success on receiving valid email and code")
	}

	if err != nil {
		t.Error("failed to return nil on receiving valid email and code")
	}
}
