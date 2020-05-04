package internal

import (
	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	iamcredentials1 "cloud.google.com/go/iam/credentials/apiv1"
	"context"
	"fmt"
	"github.com/golang/protobuf/ptypes/timestamp"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
	"google.golang.org/genproto/googleapis/iam/credentials/v1"
	"time"
)

func GetAuthToken(projectID string) (token string, err error) {

	ctx := context.Background()
	client, err := iamcredentials1.NewIamCredentialsClient(ctx)
	if err != nil {
		return "", fmt.Errorf("NewClient: %v", err)
	}
	defer client.Close()

	scope := []string{"full-control"}
	//projects/-/serviceAccounts/{ACCOUNT_EMAIL_OR_UNIQUEID}
	req := &credentials.GenerateAccessTokenRequest{
		Name:      fmt.Sprintf("projects/-/serviceAccounts/explorer-sa@%s.iam.gserviceaccount.com", projectID),
		Delegates: []string{},
		Scope:     scope,
		Lifetime:  nil,
	}

	resp, err := client.GenerateAccessToken(ctx, req)

	log.Info(resp)

	return "", nil
}

func FindNotesForProject(projectID string) ([]*grafeaspb.Note, error) {
	ctx := context.Background()
	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	defer client.Close()

	req := &grafeaspb.ListNotesRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
		//Filter: fmt.Sprintf("resourceUrl = %q", "https://gcr.io/explorer-273804/vulnerabilities-tutorial-image"),
	}

	var notesList []*grafeaspb.Note
	it := client.GetGrafeasClient().ListNotes(ctx, req)
	for {
		occ, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("occurrence iteration error: %v", err)
		}
		notesList = append(notesList, occ)
	}

	return notesList, nil
}

func findOccurrencesForProject(projectID string) ([]*grafeaspb.Occurrence, error) {
	ctx := context.Background()
	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	defer client.Close()

	req := &grafeaspb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
		//Filter: fmt.Sprintf("resourceUrl = %q", "https://gcr.io/explorer-273804/vulnerabilities-tutorial-image"),
	}

	var occurrenceList []*grafeaspb.Occurrence
	it := client.GetGrafeasClient().ListOccurrences(ctx, req)
	for {
		occ, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("occurrence iteration error: %v", err)
		}
		occurrenceList = append(occurrenceList, occ)
	}

	return occurrenceList, nil
}

func FindOccurrencesForCriteria(projectID string, image string, digest string, kind string, severity string) ([]*grafeaspb.Occurrence, error) {
	ctx := context.Background()
	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	defer client.Close()

	resourceUri := fmt.Sprintf("https://gcr.io/%s/%s@%s", projectID, image, digest)

	req := &grafeaspb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
		Filter: fmt.Sprintf("resourceUri = %q, kind = %q", resourceUri, kind),
		//Filter: fmt.Sprintf("severity = %q", "MEDIUM"),
	}

	var occurrenceList []*grafeaspb.Occurrence
	it := client.GetGrafeasClient().ListOccurrences(ctx, req)
	for {
		occ, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("occurrence iteration error: %v", err)
		}
		include := true
		if occ.Kind == grafeaspb.NoteKind_VULNERABILITY {
			details := occ.GetDetails().(*grafeaspb.Occurrence_Vulnerability)
			vulnerability := details.Vulnerability
			if vulnerability.Severity.String() != severity {
				include = false
			}
		}
		if include == true {
			occurrenceList = append(occurrenceList, occ)
		}
	}

	return occurrenceList, nil
}

func PollDiscoveryOccurrenceFinished(resourceURL, projectID string, timeout time.Duration) (*grafeaspb.Occurrence, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	defer client.Close()

	// ticker is used to poll once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Find the discovery occurrence using a filter string.
	var discoveryOccurrence *grafeaspb.Occurrence
	for discoveryOccurrence == nil {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout while retrieving discovery occurrence")
		case <-ticker.C:
			req := &grafeaspb.ListOccurrencesRequest{
				Parent: fmt.Sprintf("projects/%s", projectID),
				// Vulnerability discovery occurrences are always associated with the
				// PACKAGE_VULNERABILITY note in the "goog-analysis" GCP project.
				//Filter: fmt.Sprintf(`resourceUrl=%q AND noteProjectId="goog-analysis" AND noteId="PACKAGE_VULNERABILITY"`, resourceURL),
			}
			it := client.GetGrafeasClient().ListOccurrences(ctx, req)
			// Only one occurrence should ever be returned by ListOccurrences
			// and the given filter.
			result, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("it.Next: %v", err)
			}
			if result.GetDiscovery() != nil {
				discoveryOccurrence = result
			}
		}
	}

	// Wait for the discovery occurrence to enter a terminal state.
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for terminal state")
		case <-ticker.C:
			// Update the occurrence.
			req := &grafeaspb.GetOccurrenceRequest{Name: discoveryOccurrence.GetName()}
			updated, err := client.GetGrafeasClient().GetOccurrence(ctx, req)
			if err != nil {
				return nil, fmt.Errorf("GetOccurrence: %v", err)
			}
			switch updated.GetDiscovery().GetAnalysisStatus() {
			case grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS,
				grafeaspb.DiscoveryOccurrence_FINISHED_FAILED,
				grafeaspb.DiscoveryOccurrence_FINISHED_UNSUPPORTED:
				return discoveryOccurrence, nil
			}
		}
	}

}

func FindVulnerabilityOccurrencesForImage(resourceURL, projectID string) ([]*grafeaspb.Occurrence, error) {
	ctx := context.Background()
	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	defer client.Close()

	req := &grafeaspb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
		//Filter: fmt.Sprintf("resourceUri = %q", resourceURL),
		//Filter: fmt.Sprintf("resourceUrl = %q kind = %q", resourceURL, "NoteKind_VULNERABILITY"),
		//Filter: fmt.Sprintf("kind = %q", "NoteKind_VULNERABILITY (1)"),
		//Filter: fmt.Sprintf("kind = %q", "VULNERABILITY"),
		Filter: fmt.Sprintf("resourceUrl = %q", "https://gcr.io/explorer-273804/vulnerabilities-tutorial-image"),
	}

	var occurrenceList []*grafeaspb.Occurrence
	it := client.GetGrafeasClient().ListOccurrences(ctx, req)
	for {
		occ, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("occurrence iteration error: %v", err)
		}
		occurrenceList = append(occurrenceList, occ)
	}

	return occurrenceList, nil
}

func GetOccurrence(occurrenceID, projectID string) (*grafeaspb.Occurrence, error) {
	// occurrenceID := path.Base(occurrence.Name)
	ctx := context.Background()
	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	defer client.Close()

	req := &grafeaspb.GetOccurrenceRequest{
		Name: fmt.Sprintf("projects/%s/occurrences/%s", projectID, occurrenceID),
	}
	occ, err := client.GetGrafeasClient().GetOccurrence(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("client.GetOccurrence: %v", err)
	}
	return occ, nil
}

func CreateNote(projectID string) (*grafeaspb.Note, error) {
	// occurrenceID := path.Base(occurrence.Name)
	ctx := context.Background()
	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	defer client.Close()

	t := time.Now()
	tt := timestamp.Timestamp{Seconds: t.Unix()}

	noteType := grafeaspb.Note_Attestation{Attestation: &grafeaspb.AttestationNote{
		Hint: &grafeaspb.AttestationNote_Hint{
			HumanReadableName: "My hint",
		},
		XXX_NoUnkeyedLiteral: struct{}{},
		XXX_unrecognized:     nil,
		XXX_sizecache:        0,
	}}

	note := grafeaspb.Note{
		Name:             "accepted_risk_java_deprecated",
		ShortDescription: "Accepted risk that Java version deprecated",
		LongDescription:  "Accepted risk that Java version (8.1.2) deprecated",
		Kind:             grafeaspb.NoteKind_ATTESTATION,
		RelatedUrl:       nil,
		ExpirationTime:   nil,
		CreateTime:       &tt,
		UpdateTime:       nil,
		RelatedNoteNames: nil,
		Type:             &noteType,
	}

	req := &grafeaspb.CreateNoteRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
		NoteId: "accepted_risk",
		Note:   &note,
	}

	createdNote, err := client.GetGrafeasClient().CreateNote(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("client.createNote: %v", err)
	}
	return createdNote, nil
}

func CreateOccurrence(projectID string) (*grafeaspb.Occurrence, error) {
	ctx := context.Background()
	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	defer client.Close()

	t := time.Now()
	tt := timestamp.Timestamp{Seconds: t.Unix()}
	noteName := fmt.Sprintf("projects/%v/notes/%v", projectID, "accepted_risk")

	serialisedPayload := []byte("abcde")
	occurrence := grafeaspb.Occurrence{
		Name:        "accepted_risk_java_deprecated_occ1",
		ResourceUri: "gcr.io/explorer-273804/vulnerabilities-tutorial-image@sha256:ecc6b82ae27e3f41ff9685fc2b23fc1984ed8746d506c1715bf355036c230aad",
		NoteName:    noteName,
		Kind:        grafeaspb.NoteKind_ATTESTATION,
		Remediation: "None",
		CreateTime:  &tt,
		Details:     &grafeaspb.Occurrence_Attestation{Attestation: &grafeaspb.AttestationOccurrence{SerializedPayload: serialisedPayload}},
	}

	req := &grafeaspb.CreateOccurrenceRequest{
		Parent:     fmt.Sprintf("projects/%s", projectID),
		Occurrence: &occurrence,
	}

	createdOccurrence, err := client.GetGrafeasClient().CreateOccurrence(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("client.createNote: %v", err)
	}
	return createdOccurrence, nil
}

func GetDiscoveryInfo(resourceURL, projectID string) error {
	// resourceURL := fmt.Sprintf("https://gcr.io/my-project/my-image")
	ctx := context.Background()
	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("NewClient: %v", err)
	}
	defer client.Close()

	req := &grafeaspb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
		Filter: fmt.Sprintf(`kind="DISCOVERY"`, resourceURL),
		//Filter: fmt.Sprintf(`kind="DISCOVERY" AND resourceUrl=%q`, resourceURL),
	}
	it := client.GetGrafeasClient().ListOccurrences(ctx, req)
	for {
		occ, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("occurrence iteration error: %v", err)
		}
		log.Info(occ)
	}
	return nil
}
