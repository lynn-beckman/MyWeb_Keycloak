import { Component, OnInit } from '@angular/core';
import { OAuthService } from 'angular-oauth2-oidc';
import { filter } from 'rxjs/operators';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
})
export class HomeComponent implements OnInit {

  userProfile: object | undefined;

  constructor(private oauthService: OAuthService) {
    this.oauthService.events
      .pipe(filter((e) => e.type === 'token_received'))
      .subscribe((_) => {
        console.debug('state', this.oauthService.state);
        this.loadUserProfile();
        const scopes = this.oauthService.getGrantedScopes();
        console.debug('scopes', scopes);
      });
  }

  loadUserProfile(): void {
    if(this.oauthService.hasValidAccessToken())
    {
      this.oauthService.loadUserProfile().then((up) => (this.userProfile = up));
    }
  }

  ngOnInit() {
    this.loadUserProfile();
  }
}
